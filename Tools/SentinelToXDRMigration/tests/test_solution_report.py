from __future__ import annotations

import ast
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from sentinel_xdr_migration.converter import convert_solution
from sentinel_xdr_migration.artifacts import report_directory
from sentinel_xdr_migration.report_dashboard import _deployment_planning_html
from sentinel_xdr_migration.solution_report import (
    _package_resource_inventory,
    _planning_summary,
    _preflight_projection,
    _selected_packaging_report,
    build_solution_report,
)
from test_converter import RULE


class SolutionReportTests(unittest.TestCase):
    def test_selected_package_report_is_bound_to_current_workflow_attempt(self) -> None:
        report_bytes = b"current package report"
        report_hash = hashlib.sha256(report_bytes).hexdigest()
        package_input_hash = "a" * 64
        artifact_hashes = {
            name: (value * 64)[:64]
            for name, value in (
                ("mainTemplate", "1"),
                ("createUiDefinition", "2"),
                ("testParameters", "3"),
                ("zip", "4"),
            )
        }
        attempt_id = "current-attempt"
        selected_reference = "Logs/run/packaging.v3_1.current-attempt.json"
        package_document = {
            "packager": "V3.1",
            "packageAttemptId": attempt_id,
            "workflowRunId": "selected-run",
            "packageArtifactsSha256": "b" * 64,
            "packageInputs": {"after": {"sha256": package_input_hash}},
            "packageArtifactHashes": artifact_hashes,
        }
        workflow = {
            "runId": "selected-run",
            "stages": {
                "packaging": {
                    "status": "passed",
                    "artifacts": {
                        "packageReport": selected_reference,
                        "packageAttemptId": attempt_id,
                        "packageReportSha256": report_hash,
                    },
                },
            },
            "packaging": {
                "lastSuccessful": {
                    "packageSucceeded": True,
                    "attemptId": attempt_id,
                    "packageReport": selected_reference,
                    "packageReportSha256": report_hash,
                    "packageArtifactsSha256": "b" * 64,
                    "packageInputSha256": package_input_hash,
                },
            },
        }
        resolved = Mock()
        resolved.resolve.return_value = Path("/selected-run/current-package.json")
        resolved.read_bytes.return_value = report_bytes
        with (
            patch("sentinel_xdr_migration.solution_report.report_directory", return_value=Path("/selected-run/reports")),
            patch("sentinel_xdr_migration.solution_report.resolve_artifact_reference", return_value=resolved),
            patch("sentinel_xdr_migration.solution_report._read_run_json", return_value=package_document),
        ):
            selected, reference = _selected_packaging_report(Path("/selected-run"), workflow)
        self.assertEqual(package_document, selected)
        self.assertEqual(selected_reference, reference)

        workflow["packaging"]["lastSuccessful"]["packageReport"] = "Logs/run/packaging.v3_1.json"
        with (
            patch("sentinel_xdr_migration.solution_report.report_directory", return_value=Path("/selected-run/reports")),
            patch("sentinel_xdr_migration.solution_report.resolve_artifact_reference", return_value=resolved),
            patch("sentinel_xdr_migration.solution_report._read_run_json", return_value=package_document),
        ):
            selected, reference = _selected_packaging_report(Path("/selected-run"), workflow)
        self.assertEqual({}, selected)
        self.assertIsNone(reference)

    def test_planning_consent_requires_current_bound_plan_and_preserves_component_scope(self) -> None:
        digest = "a" * 64
        contract = {
            "schemaVersion": "1.0.0",
            "status": "provisional",
            "selectedProfile": "qualification",
            "executionMode": "pairs",
            "target": {"workspaceResourceId": "<script>alert(1)</script>"},
            "planSha256": digest,
            "components": {
                "disabledRulePairValidation": {
                    "planningConsent": {"status": "approved"},
                    "resourceTypes": ["Microsoft.Security/detectionRules@2026-06-01-preview"],
                    "selectedFlags": {"disabledOnly": True},
                },
                "mockTelemetryIngestion": {
                    "planningConsent": {"status": "unknown"},
                    "conditional": True,
                },
            },
            "planningConsent": {
                "status": "approved",
                "planSha256": digest,
                "componentKeys": ["disabledRulePairValidation"],
                "resourceTypes": ["Microsoft.Security/detectionRules@2026-06-01-preview"],
                "selectedFlags": {"disabledOnly": True},
            },
            "exactScopeWriteApproval": "not-recorded",
            "readiness": "not-evaluated",
            "deploymentEvidence": "not-recorded",
        }
        with tempfile.TemporaryDirectory() as folder:
            projected = _planning_summary(
                Path(folder),
                {},
                {"packageFreshness": {"status": "current"}},
                {"deploymentPlanning": contract},
            )

        self.assertEqual("provisional", projected["deploymentPlan"]["status"])
        self.assertEqual("stale", projected["deploymentPlan"]["planningConsent"]["status"])
        self.assertEqual("not-recorded", projected["deploymentPlan"]["exactScopeWriteApproval"])
        self.assertEqual("pairs", projected["deploymentPlan"]["executionMode"])
        self.assertEqual(
            ["Microsoft.Security/detectionRules@2026-06-01-preview"],
            projected["deploymentPlan"]["components"]["disabledRulePairValidation"]["resourceTypes"],
        )
        self.assertEqual(
            "stale",
            projected["deploymentPlan"]["components"]["mockTelemetryIngestion"]["planningConsent"],
        )
        html = _deployment_planning_html({"deploymentPlanning": projected})
        self.assertIn("Qualification", html)
        self.assertIn("disabledRulePairValidation", html)
        self.assertIn("Microsoft.Security/detectionRules", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_package_inventory_reads_nested_arrays_and_language_version_two_resources(self) -> None:
        inventory = _package_resource_inventory({
            "resources": {
                "nested": {
                    "type": "Microsoft.Resources/deployments",
                    "properties": {
                        "template": {
                            "resources": [
                                {"type": "Microsoft.Security/detectionRules@2026-06-01-preview"},
                            ],
                        },
                    },
                },
                "alertRule": {
                    "type": "Microsoft.SecurityInsights/alertRules",
                    "apiVersion": "2024-03-01",
                },
            },
        })
        by_type = {item["type"]: item for item in inventory}
        self.assertEqual("2026-06-01-preview", by_type["Microsoft.Security/detectionRules"]["apiVersion"])
        self.assertEqual(
            "Microsoft.Security/detectionRules@2026-06-01-preview",
            by_type["Microsoft.Security/detectionRules"]["originalType"],
        )
        self.assertEqual("2024-03-01", by_type["Microsoft.SecurityInsights/alertRules"]["apiVersion"])
        self.assertIn("languageVersion 2 resource dictionary", by_type["Microsoft.SecurityInsights/alertRules"]["sourceForms"])
        self.assertIn("nested ARM resources array", by_type["Microsoft.Security/detectionRules"]["sourceForms"])

    def test_preflight_projection_keeps_management_grant_separate_from_read_and_get(self) -> None:
        projected = _preflight_projection({
            "status": "ready",
            "requiredManagementPermission": "CustomDetection.ReadWrite.All",
            "managementPermissionGrant": {
                "status": "missing",
                "grantType": "delegated",
                "claimType": "scp",
                "permission": "CustomDetection.ReadWrite.All",
                "credentialRequestScope": "graph-resource-default",
            },
            "deploymentReadiness": "action-required",
            "authentication": {
                "status": "acquired",
                "tokenPermissionClaims": {"status": "present", "claimType": "scp"},
            },
            "permissions": {
                "readAccess": "confirmed",
                "writeAuthorization": "not-tested",
                "effectiveRole": {"status": "unknown"},
            },
            "readChecks": [{"status": "confirmed", "httpStatus": 200}],
        })
        self.assertEqual("confirmed", projected["permissions"]["readAccess"])
        self.assertEqual(200, projected["readChecks"][0]["httpStatus"])
        self.assertEqual("missing", projected["managementPermissionGrant"]["status"])
        self.assertEqual("action-required", projected["deploymentReadiness"])
        self.assertEqual("unknown", projected["effectiveRoleStatus"])
        self.assertEqual("scp", projected["tokenPermissionClaims"]["claimType"])

    def test_runtime_pass_is_blocked_when_current_advanced_hunting_query_hash_differs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "Example"
            analytic = root / "Analytic Rules"
            analytic.mkdir(parents=True)
            (analytic / "Rule.yaml").write_text(RULE, encoding="utf-8")
            convert_solution(root)
            detection_path = root / "XDR Detections/Rule.yaml"
            detection = yaml.safe_load(detection_path.read_text())
            target_query = detection["properties"]["queryCondition"]["queryText"]
            report_directory(root, create=True).joinpath(
                "runtime-validation.graph.json"
            ).write_text(json.dumps({
                "provider": "graph",
                "platform": "Microsoft Defender XDR Advanced Hunting",
                "results": [{
                    "detection": "Rule.yaml",
                    "status": "passed",
                    "rowCount": 1,
                    "querySha256": hashlib.sha256(b"DeviceEvents").hexdigest(),
                }],
            }))

            report = build_solution_report(root)
            runtime = report["rules"][0]["customDetection"]["runtime"][0]
            self.assertEqual("blocked", runtime["status"])
            self.assertEqual("stale-or-missing", runtime["queryHashStatus"])
            self.assertTrue(any(
                error["stage"] == "custom-detection-runtime-validation"
                and "exact current query was not validated" in error["message"]
                for error in report["rules"][0]["errors"]
            ))

            runtime_hash = hashlib.sha256(target_query.encode()).hexdigest()
            report_path = report_directory(root) / "runtime-validation.graph.json"
            result_document = json.loads(report_path.read_text())
            result_document["results"][0]["querySha256"] = runtime_hash
            report_path.write_text(json.dumps(result_document))
            refreshed = build_solution_report(root)
            self.assertEqual(
                "passed",
                refreshed["rules"][0]["customDetection"]["runtime"][0]["status"],
            )

    def test_information_uses_manifest_with_provenance_fallback_without_status_changes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "Example"
            analytic = root / "Analytic Rules"
            analytic.mkdir(parents=True)
            (analytic / "Rule.yaml").write_text(yaml.safe_dump({
                "id": "11111111-1111-1111-1111-111111111111", "name": "Example",
                "description": "Example", "severity": "High", "queryFrequency": "1h", "queryPeriod": "4h",
                "query": "DeviceEvents | project Timestamp, DeviceId, DeviceName",
                "entityMappings": [{"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "DeviceName"}]}],
            }), encoding="utf-8")
            convert_solution(root)
            reports = report_directory(root)
            manifest_path = reports / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["results"][0].pop("informational", None)
            manifest_path.write_text(json.dumps(manifest))
            draft_path = root / "XDR Detections" / "Rule.yaml"
            draft = yaml.safe_load(draft_path.read_text())
            draft["contentProvenance"]["conversion"]["informational"] = ["Provenance fallback"]
            draft_path.write_text(yaml.safe_dump(draft))
            fallback = build_solution_report(root)
            self.assertEqual(fallback["rules"][0]["informational"], ["Provenance fallback"])
            self.assertEqual(len(fallback["rules"][0]["sourceSha256"]), 64)
            manifest["results"][0]["informational"] = []
            manifest_path.write_text(json.dumps(manifest))
            empty = build_solution_report(root)
            self.assertEqual(empty["rules"][0]["informational"], [])
            self.assertEqual(empty["summary"]["informational"], 0)
            self.assertEqual(fallback["summary"]["informational"], 1)
            self.assertEqual(fallback["summary"]["rulesWithInformation"], 1)
            self.assertEqual(
                {key: value for key, value in empty["summary"].items() if key not in {"informational", "rulesWithInformation"}},
                {key: value for key, value in fallback["summary"].items() if key not in {"informational", "rulesWithInformation"}},
            )
            manifest["results"][0]["informational"] = ["Manifest <information>"]
            manifest_path.write_text(json.dumps(manifest))
            explicit = build_solution_report(root)
            self.assertEqual(explicit["rules"][0]["informational"], ["Manifest <information>"])
            self.assertEqual(explicit["summary"], fallback["summary"])
            self.assertIn("Manifest &lt;information&gt;", Path(explicit["htmlReport"]).read_text())

    def test_report_renderer_parses_as_python_311(self) -> None:
        source_path = (
            Path(__file__).parents[1]
            / "sentinel_xdr_migration"
            / "solution_report.py"
        )
        ast.parse(
            source_path.read_text(encoding="utf-8"),
            filename=str(source_path),
            feature_version=(3, 11),
        )

    def test_report_contains_rule_status_and_entity_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "Example"
            rules = root / "Analytic Rules"
            rules.mkdir(parents=True)
            source = {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "Example rule",
                "description": "Example",
                "severity": "High",
                "tactics": ["Execution"],
                "relevantTechniques": ["T1059"],
                "queryFrequency": "1h",
                "queryPeriod": "1h",
                "query": "Example_CL | project User",
                "entityMappings": [
                    {
                        "entityType": "Account",
                        "fieldMappings": [
                            {"identifier": "Name", "columnName": "User"}
                        ],
                    }
                ],
            }
            (rules / "Rule.yaml").write_text(
                yaml.safe_dump(source, sort_keys=False), encoding="utf-8"
            )
            convert_solution(root)
            output = root / "XDR Detections"
            reports = report_directory(root, create=True)
            (reports / "runtime-validation.log-analytics-cli.json").write_text(
                json.dumps(
                    {
                        "platform": "Microsoft Sentinel Log Analytics",
                        "provider": "log-analytics-cli",
                        "results": [
                            {
                                "detection": "Rule.yaml",
                                "status": "passed",
                                "rowCount": 1,
                                "querySha256": hashlib.sha256(
                                    source["query"].encode()
                                ).hexdigest(),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "runtime-validation.graph.json").write_text(
                json.dumps(
                    {
                        "platform": "Microsoft Defender XDR Advanced Hunting",
                        "provider": "graph",
                        "results": [
                            {
                                "detection": "Rule.yaml",
                                "status": "blocked",
                                "rowCount": 0,
                                "querySha256": hashlib.sha256(
                                    yaml.safe_load(
                                        (output / "Rule.yaml").read_text()
                                    )["properties"]["queryCondition"]["queryText"].encode()
                                ).hexdigest(),
                                "error": "table unavailable",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "mock-query-parity.json").write_text(
                json.dumps(
                    {
                        "reportPath": str(reports / "mock-query-parity.json"),
                        "comparisons": [
                            {
                                "detection": "Rule.yaml",
                                "passed": True,
                                "matchKey": {"IPAddress": "192.0.2.1"},
                                "analyticRuleRows": 1,
                                "customDetectionRows": 1,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "packaging.v3_1.json").write_text(
                json.dumps({
                    "packageReport": str(reports / "packaging.v3_1.json"),
                    "tacticProjection": [{
                        "detectionId": f"xdr-{source['id']}",
                        "authoredTactics": ["Execution", "Persistence"],
                        "packagedTactics": ["Execution"],
                        "omittedTactics": ["Persistence"],
                    }],
                }),
                encoding="utf-8",
            )

            report = build_solution_report(root)

            self.assertEqual(report["solution"], "Example")
            self.assertEqual(report["summary"]["rules"], 1)
            self.assertEqual(report["rules"][0]["queries"]["source"], source["query"])
            self.assertTrue(report["rules"][0]["queries"]["converted"])
            self.assertIn("workflow", report)
            classification = report["rules"][0]["attackClassification"]
            self.assertEqual(classification["sourceTactics"], ["Execution"])
            self.assertEqual(classification["sourceTechniques"], ["T1059"])
            self.assertEqual(classification["originalTactics"], ["Execution"])
            self.assertEqual(classification["originalTechniques"], ["T1059"])
            self.assertEqual(classification["draftTactics"], [
                {"tactic": "Execution", "techniques": [{"technique": "T1059"}]}
            ])
            self.assertEqual(
                report["rules"][0]["customDetection"]["conversionStatus"],
                "converted",
            )
            self.assertTrue(
                report["rules"][0]["customDetection"]["reviewRequired"]
            )
            self.assertIn("complete UPN", report["rules"][0]["entityRecommendation"])
            self.assertEqual(
                report["rules"][0]["analyticRule"]["runtime"][0]["status"], "passed"
            )
            self.assertEqual(
                report["rules"][0]["customDetection"]["runtime"][0]["status"],
                "blocked",
            )
            self.assertEqual(report["summary"]["analyticRuntimePassed"], 1)
            self.assertEqual(report["summary"]["customRuntimePassed"], 0)
            self.assertEqual(report["summary"]["queryParityPassed"], 1)
            self.assertEqual(report["summary"]["packagedTacticOmissions"], 1)
            self.assertEqual(
                report["rules"][0]["packagingProjection"]["omittedTactics"],
                ["Persistence"],
            )
            self.assertTrue(any(
                "not parity" in message for message in report["rules"][0]["informational"]
            ))
            self.assertEqual(report["rules"][0]["queryParity"]["status"], "passed")
            self.assertTrue(Path(report["jsonReport"]).exists())
            self.assertTrue(Path(report["htmlReport"]).exists())
            self.assertEqual(reports, Path(report["jsonReport"]).parent)
            self.assertEqual(
                ["Rule.yaml"],
                sorted(path.name for path in output.iterdir()),
            )
            html = Path(report["htmlReport"]).read_text(encoding="utf-8")
            self.assertIn("log-analytics-cli", html)
            self.assertIn("graph", html)
            self.assertIn("Query parity", html)


if __name__ == "__main__":
    unittest.main()
