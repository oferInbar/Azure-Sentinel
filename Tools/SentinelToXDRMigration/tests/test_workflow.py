from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

import yaml

from sentinel_xdr_migration.workflow import (
    complete_workflow_stage,
    initialize_workflow,
    next_workflow_stage,
    start_workflow_stage,
    workflow_status,
)
from sentinel_xdr_migration.artifacts import artifact_path, migrate_reports
from sentinel_xdr_migration.converter import convert_solution
from sentinel_xdr_migration.solution_report import build_solution_report
from test_converter import RULE


class WorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.solution = Path(self.temp.name) / "Sample"
        self.solution.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _packaging_artifacts(self, version_bump: str = "none") -> dict[str, str]:
        package = self.solution / "Package"
        package.mkdir(exist_ok=True)
        paths = {
            "mainTemplate": package / "mainTemplate.json",
            "createUiDefinition": package / "createUiDefinition.json",
            "testParameters": package / "testParameters.json",
            "zip": package / "1.0.0.zip",
        }
        for path in paths.values():
            path.write_text("{}", encoding="utf-8")
        report = artifact_path(self.solution, "packaging.v3_1.json", create_parent=True)
        report.write_text(
            json.dumps({
                "packager": "V3.1",
                "versionBump": version_bump,
                **{name: str(path) for name, path in paths.items()},
            }),
            encoding="utf-8",
        )
        return {
            "packager": "V3.1",
            "packageReport": str(report),
            **{name: str(path) for name, path in paths.items()},
        }

    def _qualification_args(self) -> dict[str, str]:
        return {
            "tenant_id": "39768270-33ce-4b90-a1a6-e0caeb3ba0ab",
            "subscription_id": "42382e39-f157-46d1-a931-b8cfd779ece5",
            "workspace_resource_id": (
                "/subscriptions/42382e39-f157-46d1-a931-b8cfd779ece5/"
                "resourceGroups/rg/providers/Microsoft.OperationalInsights/"
                "workspaces/ws"
            ),
            "workspace_customer_id": "756386d8-e2d4-4f09-905a-74b24313721f",
        }

    def _complete_passed_stage(self, stage: str) -> None:
        start_workflow_stage(self.solution, stage)
        artifacts = self._packaging_artifacts() if stage == "packaging" else None
        message = None
        if stage == "validation":
            context = workflow_status(self.solution)["context"]
            if context["workflowProfile"] == "authoring":
                artifacts = {"runtimeStatus": "environment-blocked"}
                message = (
                    "Runtime KQL validation was not run; no runtime-qualified "
                    "claim is made."
                )
            else:
                self._create_runtime_evidence()
        complete_workflow_stage(
            self.solution,
            stage,
            status="passed",
            message=message,
            artifacts=artifacts,
        )

    def _create_runtime_evidence(self) -> None:
        source_path = self.solution / "Analytic Rules" / "Rule.yaml"
        output_path = self.solution / "XDR Detections" / "Rule.yaml"
        if not source_path.exists():
            source_path.parent.mkdir(parents=True)
            source_path.write_text(RULE, encoding="utf-8")
        source = yaml.safe_load(source_path.read_text())
        if not output_path.exists():
            output_path.parent.mkdir(parents=True)
            output_path.write_text(yaml.safe_dump({
                "kind": "CustomDetection",
                "contentProvenance": {
                    "source": {"path": "Analytic Rules/Rule.yaml"},
                },
                "properties": {
                    "queryCondition": {
                        "queryText": "DeviceEvents | where Timestamp > ago(1h)",
                    },
                },
            }), encoding="utf-8")
        target = yaml.safe_load(output_path.read_text())
        for provider, query in (
            ("triage-mcp", source["query"]),
            ("graph", target["properties"]["queryCondition"]["queryText"]),
        ):
            query_hash = hashlib.sha256(query.encode()).hexdigest()
            artifact_path(
                self.solution,
                f"runtime-validation.{provider}.json",
                create_parent=True,
            ).write_text(json.dumps({
                "provider": provider,
                "platform": (
                    "Microsoft Sentinel Triage MCP"
                    if provider == "triage-mcp"
                    else "Microsoft Defender XDR Advanced Hunting"
                ),
                "results": [{
                    "detection": "Rule.yaml",
                    "status": "passed",
                    "rowCount": 0,
                    "querySha256": query_hash,
                }],
            }), encoding="utf-8")

    def test_profile_selection_is_required(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile selection is required"):
            initialize_workflow(self.solution)

    def test_initialize_creates_resumable_state(self) -> None:
        created = initialize_workflow(
            self.solution,
            workspace_resource_id="/subscriptions/test/workspaces/sample",
            version_bump="patch",
            workflow_profile="authoring",
        )
        resumed = initialize_workflow(
            self.solution,
            workspace_resource_id="/subscriptions/test/workspaces/sample",
            version_bump="patch",
            workflow_profile="authoring",
        )

        self.assertFalse(created["resumed"])
        self.assertTrue(resumed["resumed"])
        self.assertEqual(resumed["next"], "discovery")
        self.assertTrue(
            artifact_path(self.solution, "workflow-state.json").is_file()
        )
        self.assertEqual(
            resumed["stages"]["mockIngestion"]["status"],
            "notRequired",
        )
        self.assertTrue(resumed["context"]["profileSelectionConfirmed"])

    def test_stage_gate_requires_dependencies(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")

        with self.assertRaisesRegex(ValueError, "blocked by: discovery"):
            start_workflow_stage(self.solution, "conversion")

    def test_legacy_state_is_read_only_until_explicit_copy(self) -> None:
        created = initialize_workflow(self.solution, workflow_profile="authoring")
        preferred = Path(created["statePath"])
        legacy = self.solution / "XDR Detections" / "workflow-state.json"
        legacy.parent.mkdir(parents=True, exist_ok=True)
        preferred.replace(legacy)

        with self.assertWarnsRegex(UserWarning, "reading legacy"):
            resumed = workflow_status(self.solution)
        self.assertEqual(legacy, Path(resumed["statePath"]))
        self.assertFalse(preferred.is_file())
        with self.assertRaisesRegex(ValueError, "migrate-reports"):
            start_workflow_stage(self.solution, "discovery")
        migrate_reports(self.solution, apply=True)
        self.assertTrue(preferred.is_file())
        self.assertTrue(legacy.exists())
        start_workflow_stage(self.solution, "discovery")
        self.assertEqual("running", workflow_status(self.solution)["stages"]["discovery"]["status"])

    def test_failed_stage_can_be_retried(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        start_workflow_stage(self.solution, "discovery")
        complete_workflow_stage(
            self.solution,
            "discovery",
            status="failed",
            message="source metadata is incomplete",
        )

        retry = start_workflow_stage(self.solution, "discovery")

        self.assertEqual(retry["attempts"], 2)
        self.assertEqual(retry["status"], "running")

    def test_complete_stage_persists_contract_and_unlocks_next(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        start_workflow_stage(self.solution, "discovery")
        result = complete_workflow_stage(
            self.solution,
            "discovery",
            status="passed",
            message="one source rule discovered",
            artifacts={"inspection": "Reports/Sample/sentinel-xdr-migration/inspection.json"},
            evidence=["Analytic Rules/Sample.yaml"],
        )

        self.assertEqual(result["next"], "conversion")
        self.assertEqual(next_workflow_stage(self.solution)["next"], "conversion")
        persisted = workflow_status(self.solution)
        discovery = persisted["stages"]["discovery"]
        self.assertEqual(
            discovery["artifacts"]["inspection"],
            artifact_path(self.solution, "inspection.json").relative_to(self.solution).as_posix(),
        )
        self.assertEqual(discovery["evidence"], ["Analytic Rules/Sample.yaml"])

    def test_context_mismatch_is_rejected(self) -> None:
        initialize_workflow(
            self.solution,
            version_bump="patch",
            workflow_profile="authoring",
        )

        with self.assertRaisesRegex(ValueError, "workflow already uses"):
            initialize_workflow(
                self.solution,
                version_bump="minor",
                workflow_profile="authoring",
            )

    def test_authoring_profile_moves_from_packaging_to_report(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        for stage in ("discovery", "conversion", "validation", "packaging"):
            self._complete_passed_stage(stage)

        self.assertEqual(next_workflow_stage(self.solution)["next"], "report")

    def test_qualification_profile_requires_internal_test_stages(self) -> None:
        initialized = initialize_workflow(
            self.solution,
            workflow_profile="qualification",
            **self._qualification_args(),
        )
        self.assertEqual(initialized["stages"]["mockIngestion"]["status"], "pending")
        for stage in ("discovery", "conversion", "validation", "packaging"):
            self._complete_passed_stage(stage)

        self.assertEqual(next_workflow_stage(self.solution)["next"], "deployment")

    def test_authoring_profile_can_change_to_qualification_before_live_stages(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        for stage in ("discovery", "conversion", "validation", "packaging"):
            self._complete_passed_stage(stage)

        changed = initialize_workflow(
            self.solution,
            workflow_profile="qualification",
            **self._qualification_args(),
        )

        self.assertEqual("qualification", changed["context"]["workflowProfile"])
        self.assertEqual("pending", changed["stages"]["deployment"]["status"])
        self.assertEqual("deployment", changed["next"])

    def test_packaging_cannot_pass_without_v3_1_evidence(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        for stage in ("discovery", "conversion", "validation"):
            self._complete_passed_stage(stage)
        start_workflow_stage(self.solution, "packaging")

        with self.assertRaisesRegex(ValueError, "requires packager=V3.1"):
            complete_workflow_stage(
                self.solution,
                "packaging",
                status="passed",
            )

    def test_old_report_is_not_relabelled_as_v3_1(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        for stage in ("discovery", "conversion", "validation"):
            self._complete_passed_stage(stage)
        start_workflow_stage(self.solution, "packaging")
        artifacts = self._packaging_artifacts()
        report = Path(artifacts["packageReport"])
        document = json.loads(report.read_text())
        document["packager"] = "V4"
        report.write_text(json.dumps(document))
        before = report.read_bytes()
        with self.assertRaisesRegex(ValueError, "does not prove V3.1"):
            complete_workflow_stage(
                self.solution, "packaging", status="passed", artifacts=artifacts
            )
        self.assertEqual(before, report.read_bytes())

    def test_blocked_stage_requires_explanation(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        start_workflow_stage(self.solution, "discovery")

        with self.assertRaisesRegex(ValueError, "require a message"):
            complete_workflow_stage(
                self.solution,
                "discovery",
                status="blocked",
            )

    def test_validation_cannot_pass_without_current_exact_query_evidence(self) -> None:
        initialize_workflow(self.solution, workflow_profile="qualification", **self._qualification_args())
        self._complete_passed_stage("discovery")
        self._complete_passed_stage("conversion")
        self._create_runtime_evidence()
        graph_report = artifact_path(self.solution, "runtime-validation.graph.json")
        report = json.loads(graph_report.read_text())
        report["results"][0]["querySha256"] = "0" * 64
        graph_report.write_text(json.dumps(report))
        start_workflow_stage(self.solution, "validation")

        with self.assertRaisesRegex(ValueError, "every current query"):
            complete_workflow_stage(self.solution, "validation", status="passed")

    def test_environment_blocked_authoring_cannot_hide_current_kql_failure(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        self._complete_passed_stage("discovery")
        self._complete_passed_stage("conversion")
        self._create_runtime_evidence()
        source_report = artifact_path(self.solution, "runtime-validation.triage-mcp.json")
        report = json.loads(source_report.read_text())
        report["results"][0]["status"] = "failed"
        report["results"][0]["error"] = "Failed to resolve table"
        source_report.write_text(json.dumps(report))
        start_workflow_stage(self.solution, "validation")

        with self.assertRaisesRegex(ValueError, "cannot be relabeled environment-blocked"):
            complete_workflow_stage(
                self.solution,
                "validation",
                status="passed",
                message="environment unavailable",
                artifacts={"runtimeStatus": "environment-blocked"},
            )

    def test_lookback_rewrite_invalidates_completed_runtime_and_downstream_stages(self) -> None:
        initialize_workflow(self.solution, workflow_profile="qualification", **self._qualification_args())
        source_path = self.solution / "Analytic Rules" / "Rule.yaml"
        source_path.parent.mkdir()
        source = yaml.safe_load(RULE)
        source["queryPeriod"] = "4h"
        source["query"] = (
            "DeviceEvents | summarize Count=count() "
            "by TimeGenerated, AccountUpn, IPAddress"
        )
        source_path.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")
        convert_solution(self.solution)
        self._complete_passed_stage("discovery")
        self._complete_passed_stage("conversion")
        self._create_runtime_evidence()
        self._complete_passed_stage("validation")
        self._complete_passed_stage("packaging")

        source = yaml.safe_load(source_path.read_text())
        source["queryPeriod"] = "2h"
        source_path.write_text(yaml.safe_dump(source, sort_keys=False), encoding="utf-8")
        converted = convert_solution(self.solution, overwrite=True)
        self.assertEqual(1, converted["converted"])
        target_query = yaml.safe_load(
            (self.solution / "XDR Detections/Rule.yaml").read_text()
        )["properties"]["queryCondition"]["queryText"]
        self.assertIn("Timestamp >= ago(2h)", target_query)

        stages = workflow_status(self.solution)["stages"]
        self.assertEqual("blocked", stages["validation"]["status"])
        self.assertIn("previous runtime evidence is historical", stages["validation"]["message"])
        self.assertEqual("blocked", stages["packaging"]["status"])
        report = build_solution_report(self.solution)
        runtime = report["rules"][0]["customDetection"]["runtime"]
        self.assertTrue(runtime)
        self.assertEqual("blocked", runtime[0]["status"])
        sentinel_runtime = report["rules"][0]["analyticRule"]["runtime"]
        self.assertEqual("passed", sentinel_runtime[0]["status"])
        self.assertEqual("matches", sentinel_runtime[0]["queryHashStatus"])


if __name__ == "__main__":
    unittest.main()
