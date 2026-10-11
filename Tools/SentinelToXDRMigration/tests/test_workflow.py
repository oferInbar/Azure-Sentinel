from __future__ import annotations

import json
import hashlib
import io
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import yaml

from sentinel_xdr_migration.workflow import (
    complete_workflow_stage,
    initialize_workflow,
    next_workflow_stage,
    package_workflow_v3_1,
    _yolo_package_readiness,
    read_authoring_contract,
    refresh_yolo_authoring,
    run_yolo_authoring,
    start_workflow_stage,
    workflow_status,
)
from sentinel_xdr_migration.artifacts import artifact_path, migrate_reports, using_run
from sentinel_xdr_migration.converter import convert_solution
from sentinel_xdr_migration.packaging import package_input_identity
from sentinel_xdr_migration import cli as cli_module
from sentinel_xdr_migration.solution_report import build_solution_report
from test_converter import RULE
from sentinel_xdr_migration import workflow as workflow_module


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

    def _mock_v3_1_package(self, solution: Path, **kwargs: str) -> dict:
        artifacts = self._packaging_artifacts(kwargs["version_bump"])
        package_hashes = {
            name: hashlib.sha256(Path(artifacts[name]).read_bytes()).hexdigest()
            for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip")
        }
        inputs = package_input_identity(solution)
        attempt_id = kwargs["package_attempt_id"]
        report = {
            "status": "passed",
            "packager": "V3.1",
            "version": "1.0.0",
            "versionBump": kwargs["version_bump"],
            "requestedVersionBump": kwargs["requested_version_bump"],
            "effectiveVersionBump": kwargs["version_bump"],
            "packageAttemptId": attempt_id,
            "workflowRunId": kwargs["workflow_run_id"],
            "packageInputs": {"before": inputs, "after": inputs},
            "packageArtifactHashes": package_hashes,
            "packageArtifactsSha256": hashlib.sha256(
                json.dumps(package_hashes, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            **{
                name: artifacts[name]
                for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip")
            },
        }
        report_path = Path(artifacts["packageReport"])
        report_path.write_text(json.dumps(report), encoding="utf-8")
        artifacts["packageReport"] = str(report_path)
        return {
            **report,
            "solution": str(solution),
            "packageReport": str(report_path),
            "workflowArtifacts": {
                "packager": "V3.1",
                "packageReport": str(report_path),
                **{
                    name: artifacts[name]
                    for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip")
                },
            },
        }

    def _prepare_workflow_for_package(self, version_bump: str = "patch") -> str:
        initialized = initialize_workflow(
            self.solution,
            version_bump=version_bump,
            workflow_profile="authoring",
        )
        for stage in ("discovery", "conversion", "validation"):
            self._complete_passed_stage(stage)
        return initialized["runId"]

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

    def _create_source_rules(self, count: int = 1) -> list[Path]:
        paths = []
        for index in range(count):
            path = self.solution / "Analytic Rules" / "Nested" / f"Rule{index}.yaml"
            path.parent.mkdir(parents=True, exist_ok=True)
            document = yaml.safe_load(RULE)
            document["id"] = f"11111111-1111-1111-1111-{index + 1:012d}"
            document["name"] = f"Rule {index}"
            path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
            paths.append(path)
        return paths

    def _run_yolo(self, profile: str = "authoring", count: int = 1) -> tuple[dict, dict]:
        self._create_source_rules(count)
        initialized = initialize_workflow(
            self.solution,
            workflow_profile=profile,
            yolo=True,
            **(self._qualification_args() if profile == "qualification" else {}),
        )
        with using_run(self.solution, initialized["runId"]):
            result = run_yolo_authoring(self.solution)
            contract = read_authoring_contract(self.solution)
        return result, contract

    def _runtime_reports(self, contract: dict, *, failed_graph_rules: set[str] | None = None) -> None:
        failed_graph_rules = failed_graph_rules or set()
        run = self.solution / "Logs" / "sentinel-xdr-migration" / contract["runId"]
        source_rules = {rule["ruleId"]: rule for rule in contract["inventory"]["rules"]}
        outputs = {
            result["ruleId"]: result["target"]
            for result in contract["results"]
            if result.get("target")
        }
        graph = []
        source = []
        for rule_id, target in outputs.items():
            detection = Path(target["path"]).relative_to("XDR Detections").as_posix()
            graph.append({
                "detection": detection,
                "status": "failed" if rule_id in failed_graph_rules else "passed",
                "querySha256": target["querySha256"],
                "error": "Synthetic KQL failure" if rule_id in failed_graph_rules else None,
            })
            source.append({
                "detection": detection,
                "status": "passed",
                "querySha256": source_rules[rule_id]["querySha256"],
                "error": None,
            })
        run.mkdir(parents=True, exist_ok=True)
        (run / "runtime-validation.graph.json").write_text(
            json.dumps({"provider": "graph", "results": graph}),
            encoding="utf-8",
        )
        (run / "runtime-validation.triage-mcp.json").write_text(
            json.dumps({"provider": "triage-mcp", "results": source}),
            encoding="utf-8",
        )

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

    def test_consumed_bump_retries_with_none_and_fresh_v3_1_evidence(self) -> None:
        run_id = self._prepare_workflow_for_package("patch")
        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=self._mock_v3_1_package,
        ) as package:
            first = package_workflow_v3_1(
                self.solution,
                requested_version_bump="patch",
            )
            first_report = json.loads(Path(first["packageReport"]).read_text())
            retry = package_workflow_v3_1(
                self.solution,
                requested_version_bump="none",
            )
            retry_report = json.loads(Path(retry["packageReport"]).read_text())

            self.assertEqual(["patch", "none"], [
                call.kwargs["version_bump"] for call in package.call_args_list
            ])
            self.assertEqual("patch", first_report["effectiveVersionBump"])
            self.assertEqual("none", retry_report["requestedVersionBump"])
            self.assertEqual("none", retry_report["effectiveVersionBump"])
            self.assertNotEqual(
                first_report["packageAttemptId"],
                retry_report["packageAttemptId"],
            )
            state = workflow_status(self.solution)
            self.assertEqual(2, state["stages"]["packaging"]["attempts"])
            self.assertTrue(state["packaging"]["lastConsumedAction"]["bumpConsumed"])
            self.assertEqual("none", state["packaging"]["lastConsumedAction"]["requestedVersionBump"])
            self.assertEqual("passed", state["stages"]["packaging"]["status"])

    def test_changed_package_inputs_reject_none_and_require_a_new_bump(self) -> None:
        run_id = self._prepare_workflow_for_package("patch")
        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=self._mock_v3_1_package,
        ) as package:
            package_workflow_v3_1(self.solution, requested_version_bump="patch")
            changed_input = self.solution / "XDR Detections" / "Detection.yaml"
            changed_input.parent.mkdir(parents=True, exist_ok=True)
            changed_input.write_text("kind: CustomDetection\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "inputs changed.*explicit new version bump"):
                package_workflow_v3_1(self.solution, requested_version_bump="none")
            package.assert_called_once()

            package_workflow_v3_1(self.solution, requested_version_bump="minor")
            self.assertEqual(2, package.call_count)
            state = workflow_status(self.solution)
            self.assertEqual(
                "minor",
                state["packaging"]["lastConsumedAction"]["effectiveVersionBump"],
            )

    def test_failed_packager_consuming_bump_allows_only_hash_matching_none_retry(self) -> None:
        data = self.solution / "Data" / "Solution_Sample.json"
        data.parent.mkdir()
        data.write_text(json.dumps({"Name": "Sample", "Version": "1.2.3"}), encoding="utf-8")
        run_id = self._prepare_workflow_for_package("patch")

        def fail_after_bumping(solution: Path, **kwargs: str) -> dict:
            document = json.loads(data.read_text(encoding="utf-8"))
            document["Version"] = "1.2.4"
            data.write_text(json.dumps(document), encoding="utf-8")
            raise RuntimeError("synthetic package failure after version update")

        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=fail_after_bumping,
        ):
            with self.assertRaisesRegex(RuntimeError, "synthetic package failure"):
                package_workflow_v3_1(self.solution, requested_version_bump="patch")
            state = workflow_status(self.solution)
            self.assertTrue(state["packaging"]["lastConsumedAction"]["bumpConsumed"])
            self.assertFalse(state["packaging"]["lastConsumedAction"]["packageSucceeded"])

        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=self._mock_v3_1_package,
        ) as package:
            result = package_workflow_v3_1(self.solution, requested_version_bump="none")
            self.assertEqual("none", result["effectiveVersionBump"])
            package.assert_called_once()

    def test_stale_package_artifact_blocks_next_workflow_stage(self) -> None:
        run_id = self._prepare_workflow_for_package("none")
        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=self._mock_v3_1_package,
        ):
            result = package_workflow_v3_1(self.solution, requested_version_bump="none")
            Path(result["zip"]).write_text("stale package", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "package artifact is stale: zip"):
                start_workflow_stage(self.solution, "report")

    def test_v4_package_report_cannot_pass_current_v3_1_attempt(self) -> None:
        run_id = self._prepare_workflow_for_package("patch")

        def old_v4_report(solution: Path, **kwargs: str) -> dict:
            result = self._mock_v3_1_package(solution, **kwargs)
            report_path = Path(result["packageReport"])
            report = json.loads(report_path.read_text())
            report["packager"] = "V4"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            return result

        with using_run(self.solution, run_id), mock.patch.object(
            workflow_module,
            "package_solution_v3_1",
            side_effect=old_v4_report,
        ):
            with self.assertRaisesRegex(ValueError, "does not prove V3.1"):
                package_workflow_v3_1(
                    self.solution,
                    requested_version_bump="patch",
                )
            state = workflow_status(self.solution)
            self.assertEqual("failed", state["stages"]["packaging"]["status"])
            self.assertIsNone(state["packaging"]["lastSuccessful"])

    def test_yolo_package_cli_routes_through_workflow_gates(self) -> None:
        self._create_source_rules()
        initialized = initialize_workflow(
            self.solution,
            workflow_profile="authoring",
            yolo=True,
        )
        with mock.patch.object(cli_module, "configure_logging"), mock.patch.object(
            cli_module,
            "package_workflow_v3_1",
            return_value={"packager": "V3.1"},
        ) as workflow_package:
            result = cli_module.main([
                "package-v3-1",
                "--solution", str(self.solution),
                "--run-id", initialized["runId"],
                "--version-bump", "patch",
            ])

        self.assertEqual(0, result)
        workflow_package.assert_called_once_with(
            str(self.solution),
            requested_version_bump="patch",
        )

    def test_yolo_review_required_rule_blocks_package_without_clearing_it(self) -> None:
        self._create_source_rules()
        initialized = initialize_workflow(
            self.solution,
            workflow_profile="authoring",
            yolo=True,
        )
        state = workflow_status(self.solution)
        state["stages"]["validation"]["status"] = "passed"
        record = {
            "inventory": {"rules": [{"ruleId": "source-rule"}]},
            "results": [{
                "ruleId": "source-rule",
                "status": "migrated",
                "conversionStatus": "converted",
                "validationStatus": "passed",
                "reviewRequired": True,
                "target": {"structurallyValid": True},
                "findings": [],
            }],
        }
        with mock.patch.object(
            workflow_module,
            "_current_yolo_record",
            return_value=(record, b""),
        ):
            with self.assertRaisesRegex(ValueError, "explicit-review"):
                _yolo_package_readiness(
                    self.solution,
                    Path(initialized["statePath"]),
                    state,
                )
        self.assertTrue(record["results"][0]["reviewRequired"])

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

    def test_yolo_freezes_complete_nested_inventory_and_keeps_authoring_opt_in(self) -> None:
        paths = self._create_source_rules(2)
        with self.assertRaisesRegex(ValueError, "profile selection is required"):
            initialize_workflow(self.solution, yolo=True)
        initialized = initialize_workflow(
            self.solution,
            workflow_profile="authoring",
            yolo=True,
        )
        self.assertTrue(initialized["resumed"] is False)
        self.assertEqual(1, initialized["authoring"]["currentContract"]["revision"])
        with using_run(self.solution, initialized["runId"]):
            record = read_authoring_contract(self.solution)
        self.assertEqual(2, record["coverage"]["N"])
        self.assertEqual(
            {path.relative_to(self.solution).as_posix() for path in paths},
            {rule["path"] for rule in record["inventory"]["rules"]},
        )
        self.assertEqual("unprocessed", record["results"][0]["status"])
        self.assertEqual(2, record["coverage"]["untested"])
        self.assertFalse(record["operationEligibility"]["packagingAuthorized"])

    def test_qualification_profile_is_explicit_and_retains_locked_target(self) -> None:
        self._create_source_rules()
        with self.assertRaisesRegex(ValueError, "locked target context"):
            initialize_workflow(
                self.solution,
                workflow_profile="qualification",
                yolo=True,
            )
        created = initialize_workflow(
            self.solution,
            workflow_profile="qualification",
            yolo=True,
            **self._qualification_args(),
        )
        self.assertTrue(created["context"]["profileSelectionConfirmed"])
        self.assertTrue(created["context"]["targetContextLocked"])
        self.assertEqual("qualification", created["context"]["workflowProfile"])

    def test_existing_legacy_run_is_not_implicitly_upgraded_to_yolo(self) -> None:
        initialize_workflow(self.solution, workflow_profile="authoring")
        self.assertNotIn("authoring", workflow_status(self.solution))
        with self.assertRaisesRegex(ValueError, "cannot be enabled on an existing legacy run"):
            initialize_workflow(
                self.solution,
                workflow_profile="authoring",
                yolo=True,
            )
        resumed = initialize_workflow(self.solution, workflow_profile="authoring")
        self.assertTrue(resumed["resumed"])
        self.assertNotIn("authoring", resumed)

    def test_changed_frozen_source_inventory_is_rejected_without_overwriting_edits(self) -> None:
        self._create_source_rules()
        initialized = initialize_workflow(
            self.solution,
            workflow_profile="authoring",
            yolo=True,
        )
        source = self.solution / "Analytic Rules" / "Nested" / "Rule0.yaml"
        edited = source.read_text(encoding="utf-8") + "\n# preserve owner edit\n"
        source.write_text(edited, encoding="utf-8")
        with using_run(self.solution, initialized["runId"]):
            with self.assertRaisesRegex(ValueError, "frozen YOLO source inventory is stale"):
                run_yolo_authoring(self.solution)
        self.assertEqual(edited, source.read_text(encoding="utf-8"))
        self.assertFalse((self.solution / "XDR Detections" / "Nested" / "Rule0.yaml").exists())

    def test_changed_generated_target_is_rejected_and_preserved_on_refresh(self) -> None:
        _, record = self._run_yolo(count=1)
        target = self.solution / record["results"][0]["target"]["path"]
        edited = target.read_text(encoding="utf-8") + "\n# preserve owner edit\n"
        target.write_text(edited, encoding="utf-8")
        with using_run(self.solution, record["runId"]):
            with self.assertRaisesRegex(ValueError, "generated target hash is stale"):
                refresh_yolo_authoring(self.solution)
        self.assertEqual(edited, target.read_text(encoding="utf-8"))

    def test_synthetic_yolo_flow_reuses_existing_converter_validator_and_never_packages(self) -> None:
        result, record = self._run_yolo(count=1)
        self.assertEqual(1, record["coverage"]["N"])
        self.assertEqual(1, record["coverage"]["M"])
        self.assertEqual("migrated", record["results"][0]["status"])
        self.assertEqual("blocked", result["validationStatus"])
        self.assertEqual("validation", result["next"])
        self.assertFalse(result["packageAuthorized"])
        self.assertFalse(result["qualificationAuthorized"])
        self.assertFalse(result["prCreationAuthorized"])
        stages = workflow_status(
            self.solution
        )["stages"]
        self.assertEqual("passed", stages["conversion"]["status"])
        self.assertEqual("blocked", stages["validation"]["status"])
        self.assertEqual("pending", stages["packaging"]["status"])

    def test_yolo_stop_is_durable_after_later_results_improve(self) -> None:
        result, record = self._run_yolo(count=3)
        self.assertEqual(3, record["coverage"]["M"])
        self.assertEqual("active", result["status"])
        with using_run(self.solution, record["runId"]):
            self._runtime_reports(
                record,
                failed_graph_rules={
                    record["results"][0]["ruleId"],
                    record["results"][1]["ruleId"],
                },
            )
            stopped = refresh_yolo_authoring(self.solution)
            self.assertEqual("stopped", stopped["status"])
            self.assertEqual((3, 1, 2), (
                stopped["coverage"]["N"],
                stopped["coverage"]["M"],
                stopped["coverage"]["E"],
            ))
            first_state = workflow_status(self.solution)
            self.assertEqual("blocked", first_state["workflowStatus"])
            self.assertIsNone(first_state["next"])
            self._runtime_reports(record)
            improved = refresh_yolo_authoring(self.solution)
            self.assertEqual((3, 3, 0), (
                improved["coverage"]["N"],
                improved["coverage"]["M"],
                improved["coverage"]["E"],
            ))
            self.assertTrue(improved["coverage"]["migrationThresholdMet"])
            self.assertEqual("stopped", improved["status"])
            self.assertEqual("blocked", improved["workflowStatus"])
            self.assertIsNone(improved["next"])
            no_resume = run_yolo_authoring(self.solution)
            self.assertFalse(no_resume["workPerformed"])
            self.assertEqual("stopped", no_resume["status"])

    def test_shared_provider_error_is_recorded_without_inventing_rule_errors(self) -> None:
        result, record = self._run_yolo(count=2)
        run = self.solution / "Logs" / "sentinel-xdr-migration" / record["runId"]
        (run / "runtime-validation.graph.json").write_text(
            json.dumps({
                "provider": "graph",
                "providerFailure": {"failureKind": "provider", "error": "Graph unavailable"},
                "results": [],
            }),
            encoding="utf-8",
        )
        with using_run(self.solution, record["runId"]):
            refreshed = refresh_yolo_authoring(self.solution)
            stored = read_authoring_contract(self.solution)
        self.assertEqual(1, refreshed["environmentErrorCount"])
        self.assertEqual(0, stored["coverage"]["E"])
        self.assertEqual(2, stored["coverage"]["N"])
        self.assertEqual(1, len(stored["environmentErrors"]))

    def test_concurrent_refresh_serializes_contract_writers(self) -> None:
        _, record = self._run_yolo(count=1)
        run = self.solution / "Logs" / "sentinel-xdr-migration" / record["runId"]
        (run / "runtime-validation.graph.json").write_text(
            json.dumps({
                "provider": "graph",
                "providerFailure": {"failureKind": "provider", "error": "Graph unavailable"},
                "results": [],
            }),
            encoding="utf-8",
        )

        def refresh():
            with using_run(self.solution, record["runId"]):
                return refresh_yolo_authoring(self.solution)

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: refresh(), range(2)))
        self.assertEqual({3}, {item["authoringContract"]["revision"] for item in outcomes})
        snapshots = list((run / "authoring-contracts").glob("*.json"))
        self.assertEqual(3, len(snapshots))

    def test_interrupted_snapshot_commit_recovers_without_losing_stop_or_results(self) -> None:
        _, record = self._run_yolo(count=1)
        run = self.solution / "Logs" / "sentinel-xdr-migration" / record["runId"]
        (run / "runtime-validation.graph.json").write_text(
            json.dumps({
                "provider": "graph",
                "providerFailure": {"failureKind": "provider", "error": "Graph unavailable"},
                "results": [],
            }),
            encoding="utf-8",
        )
        original_write = workflow_module._atomic_write
        writes = 0

        def fail_state_after_snapshot(path: Path, content: bytes):
            nonlocal writes
            writes += 1
            if writes == 2:
                raise OSError("simulated crash before workflow pointer update")
            return original_write(path, content)

        with using_run(self.solution, record["runId"]):
            with mock.patch.object(workflow_module, "_atomic_write", side_effect=fail_state_after_snapshot):
                with self.assertRaisesRegex(OSError, "simulated crash"):
                    refresh_yolo_authoring(self.solution)
            recovered = refresh_yolo_authoring(self.solution)
            self.assertEqual(3, recovered["authoringContract"]["revision"])
            state = workflow_status(self.solution)
            self.assertEqual(recovered["authoringContract"], state["authoring"]["currentContract"])
            self.assertEqual(1, recovered["environmentErrorCount"])

    def test_atomic_state_write_failure_leaves_previous_state_and_no_partial_file(self) -> None:
        self._create_source_rules()
        created = initialize_workflow(
            self.solution,
            workflow_profile="authoring",
            yolo=True,
        )
        with using_run(self.solution, created["runId"]):
            state_path = Path(workflow_status(self.solution)["statePath"])
            before = state_path.read_bytes()
            with mock.patch.object(workflow_module.os, "replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    start_workflow_stage(self.solution, "discovery")
            self.assertEqual(before, state_path.read_bytes())
            self.assertEqual([], list(state_path.parent.glob(".workflow-state.json.*.tmp")))

    def test_cli_yolo_is_explicit_and_requires_an_exact_run_id(self) -> None:
        from sentinel_xdr_migration.cli import main

        self._create_source_rules()
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            init_code = main([
                "workflow-init",
                "--solution", str(self.solution),
                "--workflow-profile", "authoring",
                "--yolo",
            ])
        self.assertEqual(0, init_code, stderr.getvalue())
        initialized = json.loads(stdout.getvalue())
        self.assertEqual("yolo", initialized["authoring"]["mode"])

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            missing_run_code = main([
                "workflow-yolo",
                "--solution", str(self.solution),
            ])
        self.assertEqual(2, missing_run_code)
        self.assertIn("explicit --run-id", stderr.getvalue())

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
            run_code = main([
                "workflow-yolo",
                "--solution", str(self.solution),
                "--run-id", initialized["runId"],
            ])
        self.assertEqual(1, run_code)
        outcome = json.loads(stdout.getvalue())
        self.assertEqual("active", outcome["status"])
        self.assertEqual(1, outcome["coverage"]["M"])

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr), mock.patch(
            "sentinel_xdr_migration.cli.export_evidence",
            return_value={"exported": True},
        ) as export:
            export_code = main([
                "export-evidence",
                "--solution", str(self.solution),
                "--run-id", initialized["runId"],
                "--include-authoring-contract",
            ])
        self.assertEqual(0, export_code, stderr.getvalue())
        self.assertTrue(export.call_args.kwargs["authoring_contract"]["inventory"]["complete"])
        self.assertEqual({"exported": True}, json.loads(stdout.getvalue()))


if __name__ == "__main__":
    unittest.main()
