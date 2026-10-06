from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PACKAGER = ROOT / "Tools" / "Create-Azure-Sentinel-Solution"
TRACKING_ID = "pid-399fb80b-c914-4257-b61e-91ab73733888-partnercenter"
ABSENT = object()


def ps_literal(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required")
class AttributionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix=".v3-1-test-", dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.repository = Path(self.temp.name)
        self.solution = self.repository / "Solutions" / "Sample"
        self.data = self.solution / "Data" / "Solution_Sample.json"
        self.metadata = self.solution / "SolutionMetadata.json"
        self.data.parent.mkdir(parents=True)
        self.metadata.write_text("{}", encoding="utf-8")

    def run_ps(self, command: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Stop'; " + command],
            cwd=self.repository, capture_output=True, text=True,
        )

    def write_metadata(self, tracking_id=ABSENT) -> None:
        value = {
            "publisherId": "testpublisher",
            "offerId": "test-sentinel",
            "version": "3.1.0",
            "firstPublishDate": "2021-01-01",
            "providers": ["Microsoft"],
            "categories": {"domains": ["Security"]},
            "support": {"name": "Test", "tier": "Microsoft", "link": "https://example.com"},
        }
        if tracking_id is not ABSENT:
            value["trackingId"] = tracking_id
        self.metadata.write_text(json.dumps(value), encoding="utf-8")

    def helper(self, tracking_id=ABSENT, warn: bool = True) -> subprocess.CompletedProcess:
        self.write_metadata(tracking_id)
        return self.run_ps(
            f". {ps_literal(PACKAGER / 'common/customerUsageAttribution.ps1')}; "
            "$template = [pscustomobject]@{ resources = @() }; "
            f"Add-CustomerUsageAttribution -SolutionMetadataPath {ps_literal(self.metadata)} "
            f"-Template $template -WarnIfMissing ${str(warn).lower()}; "
            "$template | ConvertTo-Json -Depth 30"
        )

    def test_absent_null_and_blank_continue_with_actionable_warning(self) -> None:
        for value in (ABSENT, None, "", " \t"):
            with self.subTest(value=value):
                result = self.helper(value)
                self.assertEqual(0, result.returncode, result.stderr)
                for text in ("No attribution marker", "Partner Center", "Technical configuration",
                             "SolutionMetadata.json", "rebuild", "https://learn.microsoft.com/"):
                    self.assertIn(text, result.stdout)
        result = self.helper(warn=False)
        self.assertEqual({"resources": []}, json.loads(result.stdout))

    def test_complete_ids_are_preserved_and_marker_shape_is_exact(self) -> None:
        for tracking_id in (TRACKING_ID, "pid-contoso-myoffer-partnercenter"):
            with self.subTest(tracking_id=tracking_id):
                result = self.helper(tracking_id)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual({"resources": [self.marker(tracking_id)]}, json.loads(result.stdout))

    @staticmethod
    def marker(tracking_id: str) -> dict:
        return {
            "type": "Microsoft.Resources/deployments",
            "apiVersion": "2025-04-01",
            "name": tracking_id,
            "properties": {
                "mode": "Incremental",
                "template": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "resources": [],
                },
            },
        }

    def test_invalid_supplied_ids_fail_instead_of_synthesizing(self) -> None:
        for value in ("399fb80b-c914-4257-b61e-91ab73733888", 123, {}, [],
                      "pid-", "pid-bad/name", "[variables('trackingId')]",
                      TRACKING_ID + " ", "pid-" + "a" * 61, "pid-ok\n"):
            with self.subTest(value=value):
                result = self.helper(value)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("Invalid trackingId", result.stderr)

    def test_duplicate_marker_is_rejected(self) -> None:
        self.write_metadata(TRACKING_ID)
        add_marker = (
            f"Add-CustomerUsageAttribution -SolutionMetadataPath {ps_literal(self.metadata)} "
            "-Template $template; "
        )
        command = (
            f". {ps_literal(PACKAGER / 'common/customerUsageAttribution.ps1')}; "
            "$template = [pscustomobject]@{ resources = @() }; "
        )
        result = self.run_ps(command + add_marker + add_marker)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Duplicate customer usage", result.stderr)

    def prepare_integration(self) -> Path:
        tools = self.repository / "Tools" / "Create-Azure-Sentinel-Solution"
        (tools / "V3").mkdir(parents=True)
        (tools / "common").mkdir()
        entry = tools / "V3" / "createSolutionV3_1.ps1"
        shutil.copyfile(PACKAGER / "V3/createSolutionV3_1.ps1", entry)
        for name in ("createSolutionLocal.ps1", "get-ccp-details.ps1", "LogAppInsights.ps1"):
            shutil.copyfile(PACKAGER / "common" / name, tools / "common" / name)
        # Run real packaging, but isolate output and exclude the unrelated full validators.
        (tools / "common/commonFunctions.ps1").write_text(
            f". {ps_literal(PACKAGER / 'common/commonFunctions.ps1')}\n"
            f"function global:git {{ $global:LASTEXITCODE = 0; {ps_literal(self.repository)} }}\n"
            "function RunArmTtkOnPackage { }\n"
            "function CheckJsonIsValid { }\n",
            encoding="utf-8",
        )
        source_id = "11111111-2222-3333-4444-555555555555"
        rule = {
            "id": source_id, "name": "Test rule", "description": "Packaging test.",
            "severity": "Medium", "kind": "Scheduled", "version": "1.0.0",
            "query": "print Test = 1", "queryFrequency": "1h", "queryPeriod": "1h",
            "triggerOperator": "gt", "triggerThreshold": 0, "tactics": ["Execution"],
            "requiredDataConnectors": [], "entityMappings": [],
        }
        detection = {
            "kind": "CustomDetection", "resourceType": "Microsoft.Security/detectionRules",
            "apiVersion": "2025-06-01",
            "contentProvenance": {"source": {"id": source_id, "version": "3.1.0"}},
            "properties": {
                "id": "22222222-2222-3333-4444-555555555555",
                "displayName": "Test detection", "status": "disabled",
                "queryCondition": {"queryText": "print Test = 1"},
                "detectionAction": {"alertTemplate": {"tactics": ["Execution"], "entityMappings": {}}},
            },
        }
        for folder, document in (("Analytic Rules", rule), ("XDR Detections", detection)):
            path = self.solution / folder / "Test.yaml"
            path.parent.mkdir()
            path.write_text("---\n" + json.dumps(document), encoding="utf-8")
        self.data.write_text(json.dumps({
            "Name": "Sample", "Author": "Test", "Description": "Test package",
            "Version": "3.1.0", "TemplateSpec": True,
            "Analytic Rules": ["Analytic Rules/Test.yaml"],
            "XDR Detections": ["XDR Detections/Test.yaml"],
            "Metadata": "SolutionMetadata.json",
            "trackingId": "pid-stale-data-partnercenter",
        }), encoding="utf-8")
        return entry

    def package(
        self, entry: Path, pipeline: bool, *,
        version_bump: str = "none", version_mode: str = "local",
        calculated_version: str = "3.1.0",
    ) -> subprocess.CompletedProcess:
        if not pipeline:
            return self.run_ps(
                f"& {ps_literal(entry)} -SolutionDataFolderPath {ps_literal(self.data.parent)} "
                f"-VersionMode {version_mode} -VersionBump {version_bump}"
            )
        return self.run_ps(
            f"$data = Get-Content -Raw {ps_literal(self.data)} | ConvertFrom-Json; "
            f"$metadata = Get-Content -Raw {ps_literal(self.metadata)} | ConvertFrom-Json; "
            "foreach ($property in $metadata.PSObject.Properties) { "
            "if ($property.Name -notin @('version', 'trackingId')) { "
            "$data | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value } }; "
            f"& {ps_literal(entry)} {ps_literal(self.repository)} 'Sample' $data "
            "'Solution_Sample.json' 'Data Connectors' 'Data' 'test' '1' '1' "
            f"{ps_literal(calculated_version)} '3.0.0' $false"
        )

    def test_local_and_positional_pipeline_preserve_nested_xdr_and_authoritative_id(self) -> None:
        entry = self.prepare_integration()
        self.write_metadata(TRACKING_ID)
        before = self.data.read_bytes(), self.metadata.read_bytes()
        for pipeline in (False, True):
            with self.subTest(pipeline=pipeline):
                result = self.package(entry, pipeline)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                package = self.solution / "Package"
                template = json.loads((package / "mainTemplate.json").read_text(encoding="utf-8-sig"))
                self.assertNotIn("languageVersion", template)
                self.assertIsInstance(template["resources"], list)
                deployments = [r for r in template["resources"] if r["type"] == "Microsoft.Resources/deployments"]
                self.assertEqual(2, len(deployments))
                self.assertIn(self.marker(TRACKING_ID), deployments)
                xdr = next(r for r in deployments if r["name"] != TRACKING_ID)
                self.assertEqual("[parameters('E5Flavor')]", xdr["condition"])
                self.assertEqual("2.0", xdr["properties"]["template"]["languageVersion"])
                self.assertIsInstance(xdr["properties"]["template"]["resources"], dict)
                self.assertEqual(
                    "disabled",
                    xdr["properties"]["template"]["resources"]["detectionRule"]["properties"]["status"],
                )
                analytic = next(r for r in template["resources"]
                                if r.get("properties", {}).get("contentKind") == "AnalyticsRule")
                self.assertEqual("[not(parameters('E5Flavor'))]", analytic["condition"])
                self.assertEqual("3.0.0", analytic["properties"]["contentSchemaVersion"])
                self.assertEqual("3.1.0", template["variables"]["_solutionVersion"])
                self.assertNotIn("trackingId", json.dumps(template))
                self.assertNotIn("pid-stale-data", json.dumps(template))
                with zipfile.ZipFile(package / "3.1.0.zip") as archive:
                    self.assertEqual(template, json.loads(archive.read("mainTemplate.json").decode("utf-8-sig")))
                self.assertEqual(before, (self.data.read_bytes(), self.metadata.read_bytes()))

    def test_entry_points_warn_for_missing_id_and_fail_for_invalid_id(self) -> None:
        entry = self.prepare_integration()
        for pipeline in (False, True):
            with self.subTest(pipeline=pipeline):
                self.write_metadata()
                result = self.package(entry, pipeline)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn("CUSTOMER USAGE ATTRIBUTION:", result.stdout)
                template = json.loads((self.solution / "Package/mainTemplate.json").read_text(encoding="utf-8-sig"))
                self.assertEqual(1, len([r for r in template["resources"] if r["type"] == "Microsoft.Resources/deployments"]))
                self.write_metadata("bad/id")
                result = self.package(entry, pipeline)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("Invalid trackingId", result.stderr)


if __name__ == "__main__":
    unittest.main()
