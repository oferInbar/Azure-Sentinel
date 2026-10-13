# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See LICENSE in the repository root.
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
import zipfile


ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "Tools/Create-Azure-Sentinel-Solution/common/commonFunctions.ps1"


def literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


@unittest.skipUnless(shutil.which("pwsh"), "PowerShell 7 is required")
class DefenderWorkbookPackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory(prefix="wb-packaging-", dir=Path.cwd())
        self.root = Path(self.scratch.name)
        self.solution = self.root / "Solutions" / "Sample"
        self.source = self.solution / "Workbooks" / "nested" / "source.json"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(json.dumps({
            "version": "Notebook/1.0",
            "items": [
                {"type": 3, "content": {"query": "SourceTable | take 1"}},
                {"query": "scope"},
            ],
        }), encoding="utf-8")
        self.notebook = {
            "version": "Notebook/1.0",
            "items": [
                {"type": 3, "content": {"query": "DeviceEvents | take 1"}},
                {"type": 1, "content": {"json": "[parameters('authored-literal')]"}},
            ],
            "fallbackResourceIds": ["[[already-bracketed]", "literal"],
            "xdrMetadata": {
                "schemaVersion": "1.0.0",
                "contentId": str(uuid.uuid5(uuid.NAMESPACE_URL, "fixture/workbook/content")),
                "instanceId": str(uuid.uuid5(uuid.NAMESPACE_URL, "fixture/workbook/instance")),
                "version": "3.1.0",
                "displayName": "Synthetic workbook",
            },
            "contentProvenance": {
                "source": {
                    "path": "Workbooks/nested/source.json",
                    "sha256": hashlib.sha256(self.source.read_bytes()).hexdigest(),
                    "originalMetadataVersion": "1.2.0",
                },
                "conversion": {
                    "tool": "sentinel-xdr-migration",
                    "version": "0.1.0",
                    "reviewRequired": False,
                    "queries": [{
                        "sourcePath": "/items/0/content/query",
                        "outputPath": "/items/0/content/query",
                        "sourceSha256": hashlib.sha256(b"SourceTable | take 1").hexdigest(),
                        "targetSha256": hashlib.sha256(b"DeviceEvents | take 1").hexdigest(),
                        "status": "converted",
                    }],
                },
                "requiredWorkloads": [{"workload": "mde", "dataTypes": ["DeviceEvents"]}],
                "requiredDataConnectors": [{"connectorId": "SyntheticConnector", "dataTypes": ["DeviceEvents"]}],
                "dependencyReviewRequired": False,
            },
        }
        self.reference = "XDR Workbooks/nested/workbook.json"
        self.target = self.solution / self.reference
        self.target.parent.mkdir(parents=True)
        self.write()
        self.data = {"Version": "3.2.7", "XDR Workbooks": [self.reference]}
        self.native = {
            "type": "Microsoft.Insights/workbooks", "name": "synthetic-native",
            "properties": {"serializedData": '{"version":"Notebook/1.0","items":[]}'},
            "condition": "[equals('native','native')]",
        }
        self.template = {
            "parameters": {},
            "variables": {"solutionId": "synthetic.publisher", "_solutionVersion": "3.2.7"},
            "resources": [{
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentPackages",
                "properties": {"contentKind": "Solution", "descriptionHtml": "", "icon": "", "dependencies": {
                    "criteria": [{"kind": "Workbook", "contentId": "native", "version": "1.0.0"}],
                }},
            }, copy.deepcopy(self.native)],
        }
        self.ui = {"parameters": {
            "outputs": {}, "steps": [], "config": {"basics": {
                "description": "{{SolutionDescription}}\n\n**Workbooks:** 1\n\n{{Logo}}",
            }},
        }}

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def write(self) -> None:
        self.target.write_text(json.dumps(self.notebook), encoding="utf-8")

    def invoke(self, *, success: bool = True, package: bool = False) -> dict:
        payload = self.root / "input.json"
        payload.write_text(json.dumps({
            "data": self.data, "template": self.template, "ui": self.ui,
        }), encoding="utf-8")
        emit = (
            f"$count=Add-XdrDefenderWorkbooksToSolution -SolutionName Sample -ContentToImport $inputData.data "
            f"-Template $template -RepositoryRoot {literal(self.root)}; "
            "Add-SolutionContentDeploymentParameters -Template $template -UiDefinition $ui; "
            "$global:baseCreateUiDefinition=$ui; Update-DefenderWorkbookDescriptionCount -Count $count; "
        )
        if package:
            metadata = self.solution / "SolutionMetadata.json"
            metadata.write_text("{}", encoding="utf-8")
            emit = (
                f"function git {{ $global:LASTEXITCODE=0; return {literal(self.root)} }}; "
                "$global:baseMainTemplate=$template; $global:baseCreateUiDefinition=$ui; "
                "$template | Add-Member -NotePropertyName metadata -NotePropertyValue "
                "([pscustomobject]@{author='';comments='{{SolutionName}}'}); "
                "$contentResourceDetails=[pscustomobject]@{apiVersion='3.0.0'}; "
                "GeneratePackage -solutionName Sample -contentToImport $inputData.data -IncludeXdrDetections $true "
                f"-SolutionMetadataPath {literal(metadata)} -SkipAttributionLookup; "
                "$count=@($template.resources | Where-Object {$_.properties.contentKind -eq 'DefenderWorkbook'}).Count; "
            )
        command = (
            "$ErrorActionPreference='Stop'; "
            f". {literal(COMMON)}; "
            f"$inputData=Get-Content -Raw -LiteralPath {literal(payload)} | ConvertFrom-Json; "
            "$template=$inputData.template; $ui=$inputData.ui; "
            + emit +
            "Write-Output '__RESULT__'; "
            "[pscustomobject]@{count=$count;template=$template;ui=$ui} | ConvertTo-Json -Depth 100 -Compress"
        )
        result = subprocess.run(
            ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, check=False,
        )
        if not success:
            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertNotIn("__RESULT__", result.stdout)
            return {"error": result.stderr}
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("__RESULT__", result.stdout)
        return json.loads(result.stdout.split("__RESULT__", 1)[1].strip())

    def test_three_records_identity_registration_projection_and_source_preservation(self) -> None:
        authored = {self.source: self.source.read_bytes(), self.target: self.target.read_bytes()}
        for index in (1, 2):
            document = copy.deepcopy(self.notebook)
            for field in ("contentId", "instanceId"):
                document["xdrMetadata"][field] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"fixture/{index}/{field}"))
            path = self.target.with_name(f"workbook-{index}.json")
            path.write_text(json.dumps(document), encoding="utf-8")
            self.data["XDR Workbooks"].append(path.relative_to(self.solution).as_posix())
            authored[path] = path.read_bytes()
        result = self.invoke()
        self.assertEqual(3, result["count"])
        resources = result["template"]["resources"]
        installs = [r for r in resources if r["type"] == "Microsoft.Resources/deployments"]
        registrations = [r for r in resources if r["type"].endswith("/contentTemplates")]
        self.assertEqual(3, len(installs))
        self.assertEqual(3, len(registrations))
        self.assertEqual(3, len({r["name"] for r in installs}))
        criteria = resources[0]["properties"]["dependencies"]["criteria"]
        self.assertEqual(3, len([c for c in criteria if c["kind"] == "DefenderWorkbook"]))
        self.assertEqual("Workbook", criteria[0]["kind"])
        for installation, registration in zip(installs, registrations):
            inner = installation["properties"]["template"]
            stored = registration["properties"]["mainTemplate"]
            self.assertEqual(inner, stored)
            self.assertEqual("inner", installation["properties"]["expressionEvaluationOptions"]["scope"])
            self.assertEqual("2.0", inner["languageVersion"])
            self.assertEqual({"provider": "MicrosoftSecurity", "version": "1.0.0"}, inner["imports"]["MicrosoftSecurity"])
            self.assertEqual("Microsoft.Security/workbooks@2026-06-01-preview", inner["resources"]["workbook"]["type"])
            props = inner["resources"]["workbook"]["properties"]
            self.assertIsInstance(props["content"], dict)
            self.assertEqual("Notebook/1.0", props["content"]["version"])
            self.assertNotIn("xdrMetadata", props["content"])
            provenance = props["content"]["contentProvenance"]
            self.assertEqual({"packageId", "packageVersion", "contentId", "contentVersion"}, set(provenance))
            self.assertEqual("3.2.7", provenance["contentVersion"])
            self.assertNotEqual(props["id"], provenance["contentId"])
            for field in ("packageId", "packageVersion", "contentId"):
                self.assertEqual(provenance[field], registration["properties"][field])
            self.assertEqual(provenance["contentVersion"], registration["properties"]["version"])
            full = registration["properties"]["contentProvenance"]
            self.assertEqual(self.notebook["contentProvenance"]["requiredWorkloads"], full["requiredWorkloads"])
            self.assertEqual(self.notebook["contentProvenance"]["requiredDataConnectors"], full["requiredDataConnectors"])
            self.assertNotIn("source", full)
            self.assertNotIn("variables(", json.dumps(provenance))
            self.assertEqual("[parameters('DeployDefenderWorkbook')]", installation["condition"])
            self.assertEqual(installation["condition"], registration["condition"])
            self.assertEqual("DefenderWorkbook", registration["properties"]["contentKind"])
            self.assertEqual("2023-04-01-preview", registration["apiVersion"])
            self.assertIn(installation["name"], registration["dependsOn"][0])
        for path, original in authored.items():
            self.assertEqual(original, path.read_bytes())
        self.assertIn("**XDR Workbooks:** 3", result["ui"]["parameters"]["config"]["basics"]["description"])

    def test_flags_ui_test_parameter_defaults_and_native_route_are_independent(self) -> None:
        result = self.invoke()
        parameters = result["template"]["parameters"]
        self.assertTrue(parameters["DeployWorkbook"]["defaultValue"])
        self.assertFalse(parameters["DeployDefenderWorkbook"]["defaultValue"])
        self.assertNotIn("DeployCustomDetection", parameters)
        outputs = result["ui"]["parameters"]["outputs"]
        self.assertEqual("[steps('contentSelection').DeployDefenderWorkbook]", outputs["DeployDefenderWorkbook"])
        elements = result["ui"]["parameters"]["steps"][0]["elements"]
        self.assertFalse(next(e for e in elements if e["name"] == "DeployDefenderWorkbook")["defaultValue"])
        native = result["template"]["resources"][1]
        condition = native.pop("condition")
        original = copy.deepcopy(self.native)
        original.pop("condition")
        self.assertEqual(original, native)
        self.assertEqual("[and(parameters('DeployWorkbook'), equals('native','native'))]", condition)
        self.assertNotIn("DeployWorkbook", json.dumps(result["template"]["resources"][2:]))

    def test_generate_package_writes_independent_test_parameters_and_zip(self) -> None:
        original = self.target.read_bytes()
        result = self.invoke(package=True)
        package = self.solution / "Package"
        parameters = json.loads((package / "testParameters.json").read_text(encoding="utf-8-sig"))
        self.assertEqual(result["template"]["parameters"], parameters)
        self.assertTrue(parameters["DeployWorkbook"]["defaultValue"])
        self.assertFalse(parameters["DeployDefenderWorkbook"]["defaultValue"])
        with zipfile.ZipFile(package / "3.2.7.zip") as archive:
            template = json.loads(archive.read("mainTemplate.json"))
            ui = json.loads(archive.read("createUiDefinition.json"))
        self.assertEqual(4, len(template["resources"]))
        self.assertEqual("[steps('contentSelection').DeployDefenderWorkbook]", ui["parameters"]["outputs"]["DeployDefenderWorkbook"])
        self.assertEqual(original, self.target.read_bytes())
        self.assertIn("**XDR Workbooks:** 1", ui["parameters"]["config"]["basics"]["description"])

    def test_empty_selection_never_scans_or_emits_flag(self) -> None:
        self.data["XDR Workbooks"] = []
        result = self.invoke()
        self.assertEqual(0, result["count"])
        self.assertNotIn("DeployDefenderWorkbook", result["template"]["parameters"])
        self.assertEqual(2, len(result["template"]["resources"]))

    def test_existing_files_require_selection_and_selection_must_be_array(self) -> None:
        for value in (None, "[]", {}, [7], [None]):
            with self.subTest(value=value):
                if value is None:
                    self.data.pop("XDR Workbooks", None)
                else:
                    self.data["XDR Workbooks"] = value
                self.invoke(success=False)

    def test_no_workbook_directory_does_not_add_selection(self) -> None:
        shutil.rmtree(self.solution / "XDR Workbooks")
        self.data.pop("XDR Workbooks")
        result = self.invoke()
        self.assertEqual(0, result["count"])
        self.assertNotIn("DeployDefenderWorkbook", result["template"]["parameters"])

    def test_version_bounds_and_package_boundary(self) -> None:
        for version in ("3.0.9", "4.0.0", "Notebook/1.0", "3.1", "03.1.0", "3.01.0"):
            with self.subTest(version=version):
                self.notebook["xdrMetadata"]["version"] = version
                self.write()
                self.invoke(success=False)
        self.notebook["xdrMetadata"]["version"] = "3.1.0"
        self.write()
        self.template["variables"]["_solutionVersion"] = "4.0.0"
        self.invoke(success=False)
        self.template["variables"]["_solutionVersion"] = "3.2.6"
        self.invoke(success=False)

    def test_review_missing_arrays_unknown_workload_and_stale_source_block(self) -> None:
        baseline = copy.deepcopy(self.notebook)
        mutations = [
            ("conversion", "reviewRequired", True), ("conversion", "reviewRequired", None),
            ("conversion", "tool", ""), ("conversion", "version", None),
            (None, "dependencyReviewRequired", True), (None, "dependencyReviewRequired", None),
            (None, "requiredWorkloads", None), (None, "requiredDataConnectors", "[]"),
            (None, "requiredWorkloads", [{"workload": "unknown", "dataTypes": []}]),
            (None, "requiredDataConnectors", [{"connectorId": "Connector", "dataTypes": [7]}]),
            ("source", "sha256", "a" * 64), ("source", "path", "../outside.json"),
        ]
        for section, field, value in mutations:
            with self.subTest(field=field, value=value):
                self.notebook = copy.deepcopy(baseline)
                container = self.notebook["contentProvenance"]
                if section:
                    container = container[section]
                container[field] = value
                self.write()
                self.invoke(success=False)

    def test_selection_paths_duplicates_and_symlinks_fail_closed(self) -> None:
        for selection in (
            [self.reference, self.reference],
            [self.reference, f"Solutions/Sample/{self.reference}"],
            ["../outside.json"], ["Workbooks/nested/source.json"],
            ["/absolute.json"], ["XDR Workbooks/../Workbooks/nested/source.json"],
        ):
            with self.subTest(selection=selection):
                self.data["XDR Workbooks"] = selection
                self.invoke(success=False)
        link = self.target.with_name("link.json")
        link.symlink_to(self.target)
        self.data["XDR Workbooks"] = [link.relative_to(self.solution).as_posix()]
        self.invoke(success=False)
        link.unlink()
        source_link = self.source.with_name("link.json")
        source_link.symlink_to(self.source)
        self.notebook["contentProvenance"]["source"]["path"] = "Workbooks/nested/link.json"
        self.write()
        self.data["XDR Workbooks"] = [self.reference]
        self.invoke(success=False)

    def test_colliding_authored_identities_are_not_rewritten(self) -> None:
        self.notebook["xdrMetadata"]["instanceId"] = self.notebook["xdrMetadata"]["contentId"]
        self.write()
        self.invoke(success=False)
        self.notebook["xdrMetadata"]["instanceId"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "fixture/other"))
        self.write()
        other = self.target.with_name("other.json")
        other.write_bytes(self.target.read_bytes())
        self.data["XDR Workbooks"].append(other.relative_to(self.solution).as_posix())
        self.invoke(success=False)

    def test_arm_looking_strings_escape_only_deployment_copies(self) -> None:
        self.notebook["xdrMetadata"]["displayName"] = "[authored title]"
        self.notebook["items"].append({"type": 1, "content": {"json": ["[literal]", None, True, 42]}})
        self.write()
        original = self.target.read_bytes()
        result = self.invoke()
        installation = result["template"]["resources"][2]
        properties = installation["properties"]["template"]["resources"]["workbook"]["properties"]
        self.assertEqual("[[authored title]", properties["name"])
        self.assertEqual("[[parameters('authored-literal')]", properties["content"]["items"][1]["content"]["json"])
        self.assertEqual("[[[already-bracketed]", properties["content"]["fallbackResourceIds"][0])
        self.assertEqual(["[[literal]", None, True, 42], properties["content"]["items"][2]["content"]["json"])
        self.assertEqual(original, self.target.read_bytes())
        self.assertEqual("[[authored title]", result["template"]["resources"][3]["properties"]["displayName"])

    def test_query_current_hash_blockers_and_pruned_scope_record(self) -> None:
        baseline = copy.deepcopy(self.notebook)
        for mutation in ("stale", "blocked", "missing-pointer", "missing-array"):
            with self.subTest(mutation=mutation):
                self.notebook = copy.deepcopy(baseline)
                conversion = self.notebook["contentProvenance"]["conversion"]
                if mutation == "missing-array":
                    conversion.pop("queries")
                elif mutation == "stale":
                    self.notebook["items"][0]["content"]["query"] += " "
                elif mutation == "blocked":
                    conversion["queries"][0]["status"] = "needs-review"
                else:
                    conversion["queries"][0]["outputPath"] = "/items/99/query"
                self.write()
                self.invoke(success=False)
        self.notebook = copy.deepcopy(baseline)
        self.notebook["contentProvenance"]["conversion"]["queries"].append({
            "sourcePath": "/items/1/query", "sourceSha256": hashlib.sha256(b"scope").hexdigest(),
            "outputPath": None, "targetSha256": None, "status": "removed-scope-helper",
        })
        self.write()
        self.assertEqual(1, self.invoke()["count"])

    def test_no_query_notebook_keeps_complete_layout(self) -> None:
        self.notebook["items"] = [{"type": 1, "name": "text-only", "content": {"json": "fixture text"}}]
        self.notebook["contentProvenance"]["conversion"]["queries"] = []
        self.notebook["contentProvenance"]["requiredWorkloads"] = []
        self.notebook["contentProvenance"]["requiredDataConnectors"] = []
        self.source.write_text(json.dumps({"version": "Notebook/1.0", "items": []}), encoding="utf-8")
        self.notebook["contentProvenance"]["source"]["sha256"] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.write()
        result = self.invoke()
        content = result["template"]["resources"][2]["properties"]["template"]["resources"]["workbook"]["properties"]["content"]
        self.assertEqual(self.notebook["items"], content["items"])

    def test_nested_notebook_layout_is_not_serialized_to_truncated_text(self) -> None:
        nested = {"leaf": "[literal]"}
        for _ in range(60):
            nested = {"child": nested}
        self.notebook["items"][1]["content"]["layout"] = nested
        self.write()
        result = self.invoke(package=True)
        packaged = json.loads((self.solution / "Package/mainTemplate.json").read_text(encoding="utf-8-sig"))
        content = packaged["resources"][2]["properties"]["template"]["resources"]["workbook"]["properties"]["content"]
        value = content["items"][1]["content"]["layout"]
        for _ in range(60):
            self.assertIsInstance(value, dict)
            value = value["child"]
        self.assertEqual({"leaf": "[[literal]"}, value)
        self.assertEqual(1, result["count"])
        for _ in range(30):
            nested = {"child": nested}
        self.notebook["items"][1]["content"]["layout"] = nested
        self.write()
        self.invoke(success=False)

    def test_v3_entrypoint_method_forwarding_preserves_legacy_default(self) -> None:
        toolkit = self.root / "Tools/Create-Azure-Sentinel-Solution"
        (toolkit / "V3").mkdir(parents=True)
        (toolkit / "common").mkdir()
        (toolkit / "common/createSolutionLocal.ps1").write_text(
            "param($SolutionDataFolderPath,$VersionMode,$VersionBump,$TargetVersion,"
            "$EntryPointName,$DefaultInputPath,$ToolkitRootPath,$IncludeXdrDetections,"
            "$EnforceV31Versions,[switch]$SkipAttributionLookup,"
            "[ValidateSet('arm-ttk','lab-deployment')]$ArmValidationMethod='arm-ttk')\n"
            "[pscustomobject]@{method=$ArmValidationMethod;entry=$EntryPointName;"
            "xdr=$IncludeXdrDetections} | ConvertTo-Json -Compress\n",
            encoding="utf-8",
        )
        for entry, method in (("createSolutionV3_1.ps1", None), ("createSolutionV3_1.ps1", "lab-deployment"),
                              ("createSolutionV3.ps1", "lab-deployment")):
            with self.subTest(entry=entry, method=method):
                destination = toolkit / "V3" / entry
                shutil.copy2(ROOT / "Tools/Create-Azure-Sentinel-Solution/V3" / entry, destination)
                arguments = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                             str(destination), "-SolutionDataFolderPath", "fixture"]
                if method:
                    arguments += ["-ArmValidationMethod", method]
                result = subprocess.run(arguments, capture_output=True, text=True, check=False)
                self.assertEqual(0, result.returncode, result.stderr)
                record = json.loads(result.stdout)
                self.assertEqual(method or "arm-ttk", record["method"])
                self.assertEqual(entry == "createSolutionV3_1.ps1", record["xdr"] is True)
        legacy = (ROOT / "Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV3.ps1").read_text()
        self.assertIn('RunArmTtkOnPackage -solutionName $solutionName -isPipelineRun $false', legacy)


if __name__ == "__main__":
    unittest.main()
