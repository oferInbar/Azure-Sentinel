from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from sentinel_xdr_migration.packaging import package_solution_v3_1


class PackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.repository = Path(self.temp.name)
        self.solution = self.repository / "Solutions" / "Sample"
        data = self.solution / "Data"
        detections = self.solution / "XDR Detections"
        package = self.solution / "Package"
        script = (
            self.repository
            / "Tools"
            / "Create-Azure-Sentinel-Solution"
            / "V3"
            / "createSolutionV3_1.ps1"
        )
        data.mkdir(parents=True)
        detections.mkdir()
        package.mkdir()
        script.parent.mkdir(parents=True)
        script.write_text("", encoding="utf-8")
        contract = script.parent.parent / "common" / "contentDeploymentParameters.json"
        contract.parent.mkdir()
        contract.write_bytes((
            Path(__file__).resolve().parents[2] / "Create-Azure-Sentinel-Solution"
            / "common" / "contentDeploymentParameters.json"
        ).read_bytes())
        (detections / "Detection.yaml").write_text("kind: CustomDetection\n", encoding="utf-8")
        (data / "Solution_Sample.json").write_text(
            json.dumps({
                "Name": "Sample",
                "Version": "1.2.3",
                "XDR Detections": ["XDR Detections/Detection.yaml"],
            }),
            encoding="utf-8",
        )
        for name in (
            "mainTemplate.json",
            "createUiDefinition.json",
            "testParameters.json",
        ):
            (package / name).write_text("{}", encoding="utf-8")
        parameters = {
            "DeployCustomDetection": {"type": "bool", "defaultValue": False},
        }
        (package / "mainTemplate.json").write_text(json.dumps({"parameters": parameters}))
        (package / "testParameters.json").write_text(json.dumps(parameters))
        (package / "createUiDefinition.json").write_text(json.dumps({
            "parameters": {
                "outputs": {"DeployCustomDetection": "[steps('contentSelection').DeployCustomDetection]"},
                "steps": [{"name": "contentSelection", "elements": [{
                    "name": "DeployCustomDetection", "type": "Microsoft.Common.CheckBox",
                    "defaultValue": False,
                }]}],
            },
        }))
        with zipfile.ZipFile(package / "1.2.3.zip", "w") as archive:
            archive.writestr("mainTemplate.json", "{}")
            archive.writestr("createUiDefinition.json", "{}")

    def tearDown(self) -> None:
        self.temp.cleanup()

    @mock.patch(
        "sentinel_xdr_migration.packaging.subprocess.run",
        return_value=CompletedProcess(
            args=[],
            returncode=0,
            stdout="=======Starting Package Creation using V3.1 tool=========",
            stderr="",
        ),
    )
    @mock.patch(
        "sentinel_xdr_migration.packaging.shutil.which",
        return_value=r"C:\Program Files\PowerShell\7\pwsh.exe",
    )
    def test_runs_v3_1_and_returns_workflow_evidence(
        self,
        which: mock.Mock,
        run: mock.Mock,
    ) -> None:
        result = package_solution_v3_1(self.solution, version_bump="none")

        self.assertEqual("V3.1", result["packager"])
        self.assertEqual(1, result["xdrDetectionCount"])
        self.assertEqual("V3.1", result["workflowArtifacts"]["packager"])
        self.assertTrue(Path(result["packageReport"]).is_file())
        self.assertEqual("packaging.v3_1.json", Path(result["packageReport"]).name)
        command = run.call_args.args[0]
        self.assertIn("createSolutionV3_1.ps1", command[3])
        self.assertEqual("none", command[-1])
        self.assertFalse(any("E5" in value or "Registration" in value for value in command))
        self.assertEqual({"DeployCustomDetection": False}, result["deploymentParameters"])
        self.assertEqual("unverified", result["customDetectionRegistrationSupport"])
        self.assertEqual(self.repository, run.call_args.kwargs["cwd"])
        which.assert_called_once_with("pwsh")

    def test_rejects_missing_xdr_reference_before_packaging(self) -> None:
        data = self.solution / "Data" / "Solution_Sample.json"
        document = json.loads(data.read_text(encoding="utf-8"))
        document["XDR Detections"] = ["XDR Detections/Missing.yaml"]
        data.write_text(json.dumps(document), encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "does not exist"):
            package_solution_v3_1(self.solution, version_bump="none")

    def test_rejects_logs_as_detection_content(self) -> None:
        data = self.solution / "Data" / "Solution_Sample.json"
        document = json.loads(data.read_text())
        document["XDR Detections"] = ["Logs/sentinel-xdr-migration/config.yaml"]
        data.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "never include Logs"):
            package_solution_v3_1(self.solution, version_bump="none")

    def test_rejects_evidence_in_any_content_array(self) -> None:
        data = self.solution / "Data" / "Solution_Sample.json"
        document = json.loads(data.read_text())
        document["Playbooks"] = ["Evidence/run/evidence.json"]
        data.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "Evidence"):
            package_solution_v3_1(self.solution, version_bump="none")

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_rejects_evidence_in_marketplace_zip(self, run, which) -> None:
        run.return_value = CompletedProcess([], 0, "Starting Package Creation using V3.1 tool", "")
        with zipfile.ZipFile(self.solution / "Package" / "1.2.3.zip", "a") as archive:
            archive.writestr("eViDeNcE/run/evidence.json", "{}")
        with self.assertRaisesRegex(RuntimeError, "Evidence"):
            package_solution_v3_1(self.solution, version_bump="none")

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_rejects_runtime_logs_in_marketplace_zip(self, run, which) -> None:
        run.return_value = CompletedProcess([], 0, "Starting Package Creation using V3.1 tool", "")
        with zipfile.ZipFile(self.solution / "Package" / "1.2.3.zip", "a") as archive:
            archive.writestr("Logs/sentinel-xdr-migration/workflow-state.json", "{}")
        with self.assertRaisesRegex(RuntimeError, "must not contain Logs"):
            package_solution_v3_1(self.solution, version_bump="none")

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_old_entry_point_output_is_not_relabelled(self, run, which) -> None:
        run.return_value = CompletedProcess(
            [], 0, "Starting Package Creation using V4 tool", ""
        )
        with self.assertRaisesRegex(RuntimeError, "did not confirm the V3.1"):
            package_solution_v3_1(self.solution, version_bump="none")

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_attribution_warning_is_visible_and_persisted(self, run, which) -> None:
        warning = "WARNING: CUSTOMER USAGE ATTRIBUTION: No attribution marker."
        run.return_value = CompletedProcess(
            [], 0, f"Starting Package Creation using V3.1 tool\n{warning}", ""
        )
        with mock.patch("sys.stderr") as stderr:
            result = package_solution_v3_1(self.solution, version_bump="none")
        self.assertEqual([warning], result["warnings"])
        self.assertTrue(stderr.write.called)
        self.assertEqual(
            [warning], json.loads(Path(result["packageReport"]).read_text())["warnings"]
        )

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_failure_does_not_accept_old_artifacts(self, run, which) -> None:
        run.return_value = CompletedProcess([], 1, "", "Invalid trackingId")
        with self.assertRaisesRegex(RuntimeError, "Invalid trackingId"):
            package_solution_v3_1(self.solution, version_bump="none")

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_attribution_source_is_reported_separately_from_warnings(self, run, which) -> None:
        source = (
            "CUSTOMER USAGE ATTRIBUTION SOURCE: publisherId=test; offerId=sentinel; "
            "planId=plan; templateURL=https://catalogartifact.azureedge.net/publicartifacts/test.json; "
            "trackingId=pid-test-partnercenter; updated metadata=SolutionMetadata.json"
        )
        run.return_value = CompletedProcess(
            [], 0, f"Starting Package Creation using V3.1 tool\n{source}", ""
        )
        with mock.patch("sys.stderr") as stderr:
            result = package_solution_v3_1(self.solution, version_bump="none")
        self.assertEqual([], result["warnings"])
        self.assertEqual([source], result["attributionSources"])
        self.assertTrue(stderr.write.called)
        self.assertEqual(
            [source], json.loads(Path(result["packageReport"]).read_text())["attributionSources"]
        )

    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    def test_tactic_projection_is_information_and_registration_remains_warning(self, run, which) -> None:
        warnings = [
            "WARNING: V3.1 CONTENT SELECTION: live provider registration support remains unverified.",
        ]
        projection = {
            "detectionId": "11111111-2222-3333-4444-555555555555",
            "authoredTactics": ["Execution", "Persistence"],
            "packagedTactics": ["Execution"],
            "omittedTactics": ["Persistence"],
        }
        information = (
            "INFORMATION: V3.1 TACTIC SELECTION: Custom Detection "
            "'11111111-2222-3333-4444-555555555555' packages 'Execution'; omitted tactics: Persistence."
        )
        run.return_value = CompletedProcess(
            [],
            0,
            "Starting Package Creation using V3.1 tool\n"
            + "\n".join(warnings)
            + "\n"
            + information
            + "\nV3.1 TACTIC PROJECTION: "
            + json.dumps(projection),
            "",
        )
        with mock.patch("sys.stderr") as stderr:
            result = package_solution_v3_1(self.solution, version_bump="none")
        self.assertTrue(stderr.write.called)
        self.assertEqual(warnings, result["warnings"])
        self.assertEqual([information], result["informational"])
        self.assertEqual([projection], result["tacticProjection"])
        saved = json.loads(Path(result["packageReport"]).read_text())
        self.assertEqual(warnings, saved["warnings"])
        self.assertEqual([information], saved["informational"])
        self.assertEqual([projection], saved["tacticProjection"])


if __name__ == "__main__":
    unittest.main()
