from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel_xdr_migration import package_acceptance as acceptance
from sentinel_xdr_migration.artifacts import (
    artifact_path,
    create_run,
    using_run,
)


class PackageAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.repository = Path(self.temp.name)
        (self.repository / "Solutions").mkdir()
        self.solution = self.repository / "Solutions" / "CiscoASA"
        self.solution.mkdir()
        package = self.solution / "Package"
        package.mkdir()
        template = {
            "variables": {"_solutionVersion": "3.1.0"},
            "resources": [
                {
                    "type": "Microsoft.Resources/deployments",
                    "properties": {
                        "template": {
                            "resources": [
                                {
                                    "type": "Microsoft.Security/detectionRules@2026-06-01-preview",
                                    "properties": {"status": "disabled"},
                                }
                                for _ in range(3)
                            ]
                        }
                    },
                },
                *[
                    {
                        "type": (
                            "Microsoft.OperationalInsights/workspaces/providers/"
                            "contentTemplates"
                        ),
                        "properties": {"contentKind": "CustomDetection"},
                    }
                    for _ in range(3)
                ],
            ],
        }
        self.template_path = package / "mainTemplate.json"
        self.template_path.write_text(json.dumps(template), encoding="utf-8")
        self.template_hash = hashlib.sha256(self.template_path.read_bytes()).hexdigest()
        self.hash_patch = mock.patch.object(
            acceptance, "EXPECTED_TEMPLATE_SHA256", self.template_hash
        )
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)

        self.run_id = "20261008T083844Z-83a32aaf9cd9419c877f8625d0625d1c"
        create_run(self.solution, run_id=self.run_id)
        run_dir = (
            self.solution
            / "Logs"
            / "sentinel-xdr-migration"
            / self.run_id
        )
        run_dir.mkdir(exist_ok=True)
        self.package_report = run_dir / "packaging.v3_1.json"
        self.package_report.write_text(
            json.dumps({"status": "passed", "version": "3.1.0"}),
            encoding="utf-8",
        )
        self.validation_log = run_dir / "local-validation.full.log"
        self.validation_log.write_text(
            "local validation: 186 passed, 1 failed, 200 skipped\n",
            encoding="utf-8",
        )
        target = acceptance.APPROVED_TARGET
        self.state = {
            "runId": self.run_id,
            "workflowStatus": "failed",
            "statePath": str(run_dir / "workflow-state.json"),
            "context": {
                "workflowProfile": "authoring",
                "tenantId": target["tenantId"],
                "subscriptionId": target["subscriptionId"],
                "workspaceResourceId": target["workspaceResourceId"],
                "workspaceCustomerId": target["workspaceCustomerId"],
            },
            "stages": {
                "discovery": {"status": "passed"},
                "conversion": {"status": "passed"},
                "validation": {"status": "passed"},
                "packaging": {
                    "status": "failed",
                    "message": "1 local check failed; 200 checks skipped.",
                    "artifacts": {
                        "packageReport": str(self.package_report),
                        "localValidationLog": str(self.validation_log),
                    },
                },
            },
        }
        self.workflow_status_patch = mock.patch.object(
            acceptance, "workflow_status", return_value=self.state
        )
        self.workflow_status_patch.start()
        self.addCleanup(self.workflow_status_patch.stop)

    def _approve(self) -> dict:
        with using_run(self.solution, self.run_id):
            return acceptance.approve_package_acceptance(
                self.solution,
                approver="maintainer approval record",
                approval_text=acceptance.LOCAL_APPROVAL_TEXT,
            )

    def test_approval_records_exact_hash_target_and_failed_local_checks(self) -> None:
        with using_run(self.solution, self.run_id):
            result = acceptance.approve_package_acceptance(
                self.solution,
                approver="maintainer approval record",
                approval_text=acceptance.LOCAL_APPROVAL_TEXT,
            )
            recorded = json.loads(Path(result["approvalPath"]).read_text())

        self.assertEqual(recorded["packageTemplateSha256"], self.template_hash)
        self.assertEqual(recorded["target"], acceptance.APPROVED_TARGET)
        self.assertEqual(recorded["localChecks"]["workflowPackagingStatus"], "failed")
        self.assertIn("200 checks skipped", recorded["localChecks"]["workflowPackagingMessage"])
        self.assertEqual(recorded["resourceWriteApproval"], "not-granted")
        self.assertEqual(self.state["stages"]["packaging"]["status"], "failed")

    def test_wrong_target_does_not_record_approval(self) -> None:
        self.state["context"]["workspaceCustomerId"] = "00000000-0000-0000-0000-000000000000"
        with using_run(self.solution, self.run_id):
            with self.assertRaisesRegex(ValueError, "does not match the approved"):
                acceptance.approve_package_acceptance(
                    self.solution,
                    approver="maintainer",
                    approval_text=acceptance.LOCAL_APPROVAL_TEXT,
                )
        self.assertFalse(
            (self.solution / "Logs/sentinel-xdr-migration" / self.run_id
             / acceptance.APPROVAL_FILE).exists()
        )

    def test_approval_requires_exact_statement_and_package_hash(self) -> None:
        with using_run(self.solution, self.run_id):
            with self.assertRaisesRegex(ValueError, "approval text must exactly"):
                acceptance.approve_package_acceptance(
                    self.solution,
                    approver="maintainer",
                    approval_text="skip validation",
                )
        self.template_path.write_text('{"changed":true}', encoding="utf-8")
        with using_run(self.solution, self.run_id):
            with self.assertRaisesRegex(ValueError, "hash does not match"):
                acceptance.approve_package_acceptance(
                    self.solution,
                    approver="maintainer",
                    approval_text=acceptance.LOCAL_APPROVAL_TEXT,
                )

    @mock.patch.object(
        acceptance,
        "_resolve_exact_workspace",
        return_value={
            "name": "ContentTestCreation",
            "resourceGroup": "ContentCreation",
            "location": "eastus",
            "resourceId": acceptance.APPROVED_TARGET["workspaceResourceId"],
            "customerId": acceptance.APPROVED_TARGET["workspaceCustomerId"],
        },
    )
    @mock.patch.object(
        acceptance,
        "_run_az",
        return_value=subprocess.CompletedProcess(
            args=["az"], returncode=0, stdout='{"properties":{"provisioningState":"Succeeded"}}', stderr=""
        ),
    )
    def test_validation_runs_only_the_two_fixed_read_only_configs(
        self, run_az: mock.Mock, _workspace: mock.Mock
    ) -> None:
        self._approve()
        with using_run(self.solution, self.run_id):
            result = acceptance.validate_package_acceptance(self.solution)

        self.assertEqual(result["status"], "passed")
        self.assertEqual(
            [item["configuration"] for item in result["configurations"]],
            ["sentinel-content", "custom-detections-only"],
        )
        self.assertTrue(all(item["resourceWrites"] is False for item in result["configurations"]))
        self.assertEqual(run_az.call_count, 2)
        for call in run_az.call_args_list:
            args = call.args[0]
            self.assertIn("validate", args)
            self.assertNotIn("create", args)
            self.assertEqual(args[args.index("--subscription") + 1], acceptance.APPROVED_TARGET["subscriptionId"])

    @mock.patch.object(acceptance, "_run_az")
    def test_resource_writes_require_final_approval_and_successful_preflight(
        self, run_az: mock.Mock
    ) -> None:
        self._approve()
        with using_run(self.solution, self.run_id):
            with self.assertRaisesRegex(ValueError, "final resource-write approval"):
                acceptance.deploy_package_acceptance(self.solution, final_approval="yes")
            with self.assertRaisesRegex(ValueError, "successful ARM validation"):
                acceptance.deploy_package_acceptance(
                    self.solution,
                    final_approval=acceptance.FINAL_APPROVAL_PREFIX,
                )
        run_az.assert_not_called()

    @mock.patch.object(
        acceptance,
        "_run_az",
        return_value=subprocess.CompletedProcess(
            args=["az"], returncode=0, stdout='{"properties":{"provisioningState":"Succeeded"}}', stderr=""
        ),
    )
    def test_final_approval_deploys_both_configs_without_changing_workflow(
        self, run_az: mock.Mock
    ) -> None:
        self._approve()
        validation = {
            "status": "passed",
            "packageTemplateSha256": self.template_hash,
            "target": acceptance.APPROVED_TARGET,
            "resolvedWorkspace": {
                "name": "ContentTestCreation",
                "location": "eastus",
            },
            "configurations": [{"status": "passed"}, {"status": "passed"}],
        }
        with using_run(self.solution, self.run_id):
            validation_path = artifact_path(
                self.solution, acceptance.VALIDATION_FILE, create_parent=True
            )
            validation_path.write_text(json.dumps(validation), encoding="utf-8")
            approval_path = artifact_path(self.solution, acceptance.APPROVAL_FILE)
            approval = json.loads(approval_path.read_text(encoding="utf-8"))
            approval["armValidationStatus"] = "passed"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            result = acceptance.deploy_package_acceptance(
                self.solution,
                final_approval=acceptance.FINAL_APPROVAL_PREFIX,
            )

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(len(result["operations"]), 2)
        self.assertEqual(run_az.call_count, 2)
        self.assertTrue(
            all("create" in call.args[0] for call in run_az.call_args_list)
        )
        self.assertEqual(self.state["stages"]["packaging"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
