from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest import mock

from sentinel_xdr_migration import cli as cli_module
from sentinel_xdr_migration.packaging import (
    V31_TOOLKIT_PATHS,
    _verify_package_selection,
    _xdr_references,
    package_input_identity,
    package_solution_v3_1,
)
from sentinel_xdr_migration.workflow import (
    complete_workflow_stage,
    initialize_workflow,
    start_workflow_stage,
)


class PackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.repository = Path(self.temp.name)
        self.solution = self.repository / "Solutions" / "Sample"
        data = self.solution / "Data"
        detections = self.solution / "XDR Detections"
        package = self.solution / "Package"
        data.mkdir(parents=True)
        detections.mkdir()
        package.mkdir()
        source_root = Path(__file__).resolve().parents[3]
        for relative in V31_TOOLKIT_PATHS:
            source = source_root / relative
            destination = self.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
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

    def test_xdr_reference_array_is_explicit_and_empty_never_scans_folder(self) -> None:
        self.assertEqual([], _xdr_references(
            self.solution, {"XDR Detections": []},
        ))
        with self.assertRaisesRegex(ValueError, "missing an explicit XDR Detections array"):
            _xdr_references(self.solution, {"Name": "Sample"})
        with self.assertRaisesRegex(ValueError, "duplicate XDR Detection"):
            _xdr_references(
                self.solution,
                {"XDR Detections": [
                    "XDR Detections/Detection.yaml",
                    "XDR Detections/Detection.yaml",
                ]},
            )
        with self.assertRaisesRegex(ValueError, "must be under XDR Detections"):
            _xdr_references(
                self.solution,
                {"XDR Detections": ["XDR Detections/../Analytic Rules/Rule.yaml"]},
            )

    def test_v3_1_refuses_to_omit_an_applied_selection_plan(self) -> None:
        with mock.patch(
            "sentinel_xdr_migration.packaging_selection.verify_applied_package_selection",
            return_value={
                "plan": {"planSha256": "a" * 64},
                "receipt": {},
            },
        ), mock.patch("sentinel_xdr_migration.packaging.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "must be passed explicitly"):
                package_solution_v3_1(
                    self.solution,
                    version_bump="none",
                    workflow_run_id="selected-run",
                )
        run.assert_not_called()

    def test_template_and_zip_match_partial_selection_exclusions(self) -> None:
        data_path = self.solution / "Data" / "Solution_Sample.json"
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["XDR Detections"] = [
            "XDR Detections/Detection.yaml",
            "XDR Detections/Detection2.yaml",
        ]
        included_source = "11111111-1111-1111-1111-111111111111"
        second_included_source = "22222222-2222-2222-2222-222222222222"
        excluded_source = "33333333-3333-3333-3333-333333333333"
        data_path.write_text(json.dumps(data), encoding="utf-8")
        plan = {
            "planSha256": "a" * 64,
            "summary": {
                "outcome": "partial",
                "coveragePolicy": "strictly-greater-than-50-percent-of-original-sentinel-rules",
                "originalSourceRuleCount": 3,
                "originalSourceRuleIds": [included_source, second_included_source, excluded_source],
                "validatedMigratedSourceRuleCount": 2,
                "validatedMigratedSourceRuleIds": [included_source, second_included_source],
                "coverageNumerator": 2,
                "coverageDenominator": 3,
                "partialPublicationAllowed": True,
            },
            "selection": {
                "analyticRules": [],
                "xdrDetections": [
                    "XDR Detections/Detection.yaml",
                    "XDR Detections/Detection2.yaml",
                ],
            },
            "analyticRules": [],
            "xdrDetections": [
                {
                    "id": "xdr-included",
                    "sourceId": included_source,
                    "path": "XDR Detections/Detection.yaml",
                    "included": True,
                },
                {
                    "id": f"xdr-{second_included_source}",
                    "sourceId": second_included_source,
                    "path": "XDR Detections/Detection2.yaml",
                    "included": True,
                },
                {
                    "id": "xdr-excluded",
                    "sourceId": excluded_source,
                    "path": "XDR Detections/Failed.yaml",
                    "included": False,
                },
            ],
        }
        packaged_id = f"xdr-{included_source}"
        second_packaged_id = f"xdr-{second_included_source}"
        (self.solution / "XDR Detections" / "Detection2.yaml").write_text(
            "kind: CustomDetection\n", encoding="utf-8",
        )
        template = {
            "parameters": {"DeployCustomDetection": {"defaultValue": False}},
            "resources": [
                {
                    "type": "Microsoft.Resources/deployments",
                    "name": "xdr-install-included",
                    "properties": {
                        "template": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {
                                        "id": f"[if(true(), '{packaged_id}', '{packaged_id}')]",
                                    },
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "dependsOn": ["[resourceId('Microsoft.Resources/deployments', 'xdr-install-included')]"],
                    "properties": {
                        "contentKind": "CustomDetection",
                        "contentId": packaged_id,
                        "mainTemplate": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": f"[if(true(), '{packaged_id}', '{packaged_id}')]"},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.Resources/deployments",
                    "name": "xdr-install-included-2",
                    "properties": {
                        "template": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": second_packaged_id},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "dependsOn": ["[resourceId('Microsoft.Resources/deployments', 'xdr-install-included-2')]"],
                    "properties": {
                        "contentKind": "CustomDetection",
                        "contentId": second_packaged_id,
                        "mainTemplate": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": second_packaged_id},
                                },
                            },
                        },
                    },
                },
            ],
        }
        template_path = self.solution / "Package" / "mainTemplate.json"
        template_path.write_text(json.dumps(template), encoding="utf-8")
        zip_path = self.solution / "Package" / "selection.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("mainTemplate.json", json.dumps(template))

        result = _verify_package_selection(
            self.solution, plan, template, zip_path,
        )

        self.assertEqual(2, result["xdrDetectionIncluded"])
        self.assertTrue(result["mainTemplateVerified"])
        self.assertTrue(result["zipVerified"])
        with zipfile.ZipFile(zip_path, "a") as archive:
            archive.writestr(
                "Solutions/Sample/XDR Detections/Failed.yaml",
                f"properties:\n  id: {excluded_source}\n",
            )
        with self.assertRaisesRegex(RuntimeError, "includes explicitly excluded content"):
            _verify_package_selection(self.solution, plan, template, zip_path)
        reference_only_zip = self.solution / "Package" / "selection-reference.zip"
        with zipfile.ZipFile(reference_only_zip, "w") as archive:
            archive.writestr("mainTemplate.json", json.dumps(template))
            archive.writestr("metadata/stale.yaml", f"excluded: xdr-{excluded_source}\n")
        with self.assertRaisesRegex(RuntimeError, "contains a reference to explicitly excluded content"):
            _verify_package_selection(self.solution, plan, template, reference_only_zip)

    def test_selection_verification_counts_exact_arm_resources_not_id_substrings(self) -> None:
        included_source = "11111111-1111-1111-1111-111111111111"
        second_included_source = "22222222-2222-2222-2222-222222222222"
        excluded_source = "33333333-3333-3333-3333-333333333333"
        data_path = self.solution / "Data" / "Solution_Sample.json"
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["Analytic Rules"] = [
            "Analytic Rules/Included.yaml",
            "Analytic Rules/Included2.yaml",
        ]
        data["XDR Detections"] = [
            "XDR Detections/Included.yaml",
            "XDR Detections/Included2.yaml",
        ]
        data_path.write_text(json.dumps(data), encoding="utf-8")
        (self.solution / "Analytic Rules").mkdir()
        (self.solution / "Analytic Rules" / "Included.yaml").write_text(
            f"id: {included_source}\n", encoding="utf-8",
        )
        (self.solution / "Analytic Rules" / "Included2.yaml").write_text(
            f"id: {second_included_source}\n", encoding="utf-8",
        )
        (self.solution / "XDR Detections" / "Included.yaml").write_text(
            "kind: CustomDetection\n", encoding="utf-8",
        )
        (self.solution / "XDR Detections" / "Included2.yaml").write_text(
            "kind: CustomDetection\n", encoding="utf-8",
        )
        plan = {
            "planSha256": "c" * 64,
            "summary": {
                "outcome": "partial",
                "coveragePolicy": "strictly-greater-than-50-percent-of-original-sentinel-rules",
                "originalSourceRuleCount": 3,
                "originalSourceRuleIds": [included_source, second_included_source, excluded_source],
                "validatedMigratedSourceRuleCount": 2,
                "validatedMigratedSourceRuleIds": [included_source, second_included_source],
                "coverageNumerator": 2,
                "coverageDenominator": 3,
                "partialPublicationAllowed": True,
            },
            "selection": {
                "analyticRules": ["Analytic Rules/Included.yaml", "Analytic Rules/Included2.yaml"],
                "xdrDetections": ["XDR Detections/Included.yaml", "XDR Detections/Included2.yaml"],
            },
            "analyticRules": [
                {"id": included_source, "path": "Analytic Rules/Included.yaml", "included": True},
                {"id": second_included_source, "path": "Analytic Rules/Included2.yaml", "included": True},
                {"id": excluded_source, "path": "Analytic Rules/Excluded.yaml", "included": False},
            ],
            "xdrDetections": [
                {
                    "id": f"xdr-{included_source}",
                    "sourceId": included_source,
                    "path": "XDR Detections/Included.yaml",
                    "included": True,
                },
                {
                    "id": f"xdr-{second_included_source}",
                    "sourceId": second_included_source,
                    "path": "XDR Detections/Included2.yaml",
                    "included": True,
                },
                {
                    "id": f"xdr-{excluded_source}",
                    "sourceId": excluded_source,
                    "path": "XDR Detections/Excluded.yaml",
                    "included": False,
                },
            ],
        }
        packaged_id = f"xdr-{included_source}"
        second_packaged_id = f"xdr-{second_included_source}"
        template = {
            "variables": {
                "analyticRuleObject1": {
                    "_analyticRulecontentId1": included_source,
                },
            },
            "resources": [
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "properties": {
                        "contentKind": "AnalyticsRule",
                        "contentId": "[variables('analyticRuleObject1')._analyticRulecontentId1]",
                        "mainTemplate": {
                            "variables": {},
                            "resources": [
                                {
                                    "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
                                    "name": "[variables('analyticRuleObject1')._analyticRulecontentId1]",
                                },
                            ],
                        },
                    },
                },
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "properties": {
                        "contentKind": "AnalyticsRule",
                        "contentId": second_included_source,
                        "mainTemplate": {
                            "resources": [
                                {
                                    "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
                                    "name": second_included_source,
                                },
                            ],
                        },
                    },
                },
                {
                    "type": "Microsoft.Resources/deployments",
                    "name": "xdr-install-included",
                    "properties": {
                        "template": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": f"['{packaged_id}']"},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "dependsOn": ["[resourceId('Microsoft.Resources/deployments', 'xdr-install-included')]"],
                    "properties": {
                        "contentKind": "CustomDetection",
                        "contentId": packaged_id,
                        "mainTemplate": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": f"[if(true(), '{packaged_id}', '{packaged_id}')]"},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.Resources/deployments",
                    "name": "xdr-install-included-2",
                    "properties": {
                        "template": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": second_packaged_id},
                                },
                            },
                        },
                    },
                },
                {
                    "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                    "dependsOn": ["[resourceId('Microsoft.Resources/deployments', 'xdr-install-included-2')]"],
                    "properties": {
                        "contentKind": "CustomDetection",
                        "contentId": second_packaged_id,
                        "mainTemplate": {
                            "resources": {
                                "detectionRule": {
                                    "type": "Microsoft.Security/detectionRules",
                                    "properties": {"id": second_packaged_id},
                                },
                            },
                        },
                    },
                },
            ],
        }
        zip_path = self.solution / "Package" / "exact-resources.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("mainTemplate.json", json.dumps(template))

        result = _verify_package_selection(self.solution, plan, template, zip_path)
        self.assertEqual(2, result["analyticRuleIncluded"])
        self.assertEqual(2, result["xdrDetectionIncluded"])

        phantom = json.loads(json.dumps(template))
        phantom["resources"] = [
            {"type": "Microsoft.Resources/deployments", "properties": {"description": included_source}}
        ]
        with self.assertRaisesRegex(RuntimeError, "Analytic Rule resources"):
            _verify_package_selection(self.solution, plan, phantom, zip_path)

        orphan_wrapper = {
            "resources": [{
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "properties": {
                    "contentKind": "AnalyticsRule",
                    "contentId": included_source,
                    "mainTemplate": {"resources": []},
                },
            }],
        }
        with self.assertRaisesRegex(RuntimeError, "content templates"):
            _verify_package_selection(self.solution, plan, orphan_wrapper, zip_path)

        duplicate = json.loads(json.dumps(template))
        duplicate["resources"].append(duplicate["resources"][0])
        with self.assertRaisesRegex(RuntimeError, "exactly 1 matching Analytic Rule"):
            _verify_package_selection(self.solution, plan, duplicate, zip_path)

    def test_empty_xdr_partial_selection_is_blocked_by_coverage_policy(self) -> None:
        data_path = self.solution / "Data" / "Solution_Sample.json"
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["XDR Detections"] = []
        data_path.write_text(json.dumps(data), encoding="utf-8")
        source_id = "11111111-1111-1111-1111-111111111111"
        plan = {
            "planSha256": "b" * 64,
            "summary": {"outcome": "partial"},
            "selection": {"analyticRules": [], "xdrDetections": []},
            "analyticRules": [],
            "xdrDetections": [{
                "id": "xdr-excluded",
                "sourceId": source_id,
                "path": "XDR Detections/Detection.yaml",
                "included": False,
            }],
        }
        template = {"resources": []}
        zip_path = self.solution / "Package" / "empty-selection.zip"
        with zipfile.ZipFile(zip_path, "w") as archive:
            archive.writestr("mainTemplate.json", json.dumps(template))

        with self.assertRaisesRegex(ValueError, "strict over-50%"):
            _verify_package_selection(self.solution, plan, template, zip_path)

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
        report = json.loads(Path(result["packageReport"]).read_text(encoding="utf-8"))
        self.assertEqual("none", report["requestedVersionBump"])
        self.assertEqual("none", report["effectiveVersionBump"])
        self.assertEqual(report["packageInputs"]["before"], report["packageInputs"]["after"])
        self.assertEqual(
            package_input_identity(self.solution)["sha256"],
            report["packageInputs"]["after"]["sha256"],
        )
        self.assertEqual(
            {"mainTemplate", "createUiDefinition", "testParameters", "zip"},
            set(report["packageArtifactHashes"]),
        )
        command = run.call_args.args[0]
        self.assertIn("createSolutionV3_1.ps1", command[3])
        self.assertNotIn("-ToolkitRootPath", command)
        self.assertEqual("none", command[-1])
        self.assertFalse(any("E5" in value or "Registration" in value for value in command))
        self.assertEqual({"DeployCustomDetection": False}, result["deploymentParameters"])
        self.assertEqual("unverified", result["customDetectionRegistrationSupport"])
        self.assertEqual(str(self.repository), result["toolkitRoot"])
        self.assertEqual(str(self.repository / V31_TOOLKIT_PATHS[0]), result["packagerScript"])
        self.assertEqual(self.repository, run.call_args.kwargs["cwd"])
        which.assert_called_once_with("pwsh")

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
    def test_partial_selection_outcome_is_persisted_in_workflow_artifacts(
        self,
        _which: mock.Mock,
        _run: mock.Mock,
    ) -> None:
        selection_plan = {
            "planSha256": "d" * 64,
            "summary": {"outcome": "partial"},
        }
        applied_selection = {
            "plan": selection_plan,
            "planPath": "Reports/Selection/package-selection-plan.json",
            "receiptPath": "Reports/Selection/package-selection-applied.json",
        }
        with (
            mock.patch(
                "sentinel_xdr_migration.packaging_selection.verify_applied_package_selection",
                return_value=applied_selection,
            ),
            mock.patch(
                "sentinel_xdr_migration.packaging._verify_package_selection",
                return_value={"status": "verified"},
            ),
        ):
            result = package_solution_v3_1(
                self.solution,
                version_bump="none",
                workflow_run_id="synthetic-package-run",
                selection_plan=selection_plan,
            )

        expected = "partial-package-validated"
        self.assertEqual(expected, result["selectionOutcome"])
        self.assertEqual(
            expected,
            result["workflowArtifacts"]["selectionOutcome"],
        )
        report = json.loads(Path(result["packageReport"]).read_text(encoding="utf-8"))
        self.assertEqual(expected, report["workflowArtifacts"]["selectionOutcome"])

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
    def test_cross_root_uses_toolkit_and_keeps_outputs_in_solution(
        self,
        which: mock.Mock,
        run: mock.Mock,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as target_directory:
            target_root = Path(target_directory)
            target_solution = target_root / "Solutions" / "Sample"
            target_solution.parent.mkdir()
            shutil.copytree(self.solution, target_solution)
            self.assertFalse((target_root / "Tools").exists())

            result = package_solution_v3_1(
                target_solution,
                version_bump="none",
                toolkit_root=self.repository,
            )

            command = run.call_args.args[0]
            self.assertIn(str(self.repository / V31_TOOLKIT_PATHS[0]), command)
            self.assertEqual(str(self.repository), command[command.index("-ToolkitRootPath") + 1])
            self.assertEqual(self.repository, Path(result["toolkitRoot"]))
            self.assertEqual(target_solution, Path(result["solution"]))
            self.assertTrue(Path(result["packageReport"]).is_relative_to(target_solution))
            self.assertTrue(Path(result["packageReport"]).is_file())
            for key in ("mainTemplate", "createUiDefinition", "testParameters", "zip"):
                self.assertTrue(Path(result[key]).is_relative_to(target_solution))
            self.assertFalse((target_root / "Tools").exists())
            self.assertEqual(target_root, run.call_args.kwargs["cwd"])
            report = json.loads(Path(result["packageReport"]).read_text(encoding="utf-8"))
            self.assertEqual(str(self.repository), report["toolkitRoot"])
            which.assert_called_once_with("pwsh")

    @unittest.skipUnless(
        shutil.which("pwsh") and shutil.which("git"),
        "PowerShell 7 and git are required",
    )
    def test_cli_runs_real_packager_for_same_and_cross_worktree_roots(self) -> None:
        source_root = Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as scratch:
            scratch_root = Path(scratch)
            module_root = scratch_root / "modules"
            module_dir = module_root / "ArmTtk"
            module_dir.mkdir(parents=True)
            (module_dir / "ArmTtk.psm1").write_text(
                "function Test-AzTemplate { param([string]$TemplatePath) @() }; "
                "Export-ModuleMember -Function Test-AzTemplate\n",
                encoding="utf-8",
            )
            module_path = str(module_root) + os.pathsep + os.environ.get("PSModulePath", "")
            with mock.patch.dict(os.environ, {"PSModulePath": module_path}):
                for mode in ("same-root", "cross-root"):
                    target_root = scratch_root / mode / "target"
                    target_root.mkdir(parents=True)
                    solution = target_root / "Solutions" / "Sample"
                    data = solution / "Data"
                    data.mkdir(parents=True)
                    (solution / "Package").mkdir()
                    (data / "Solution_Sample.json").write_text(json.dumps({
                        "Name": "Sample",
                        "Author": "Packaging Smoke Test - test@example.invalid",
                        "Version": "3.1.0",
                        "Metadata": "SolutionMetadata.json",
                        "Description": "Synthetic V3.1 packaging smoke test.",
                        "XDR Detections": [],
                    }), encoding="utf-8")
                    (solution / "SolutionMetadata.json").write_text(json.dumps({
                        "name": "Sample",
                        "version": "3.1.0",
                        "trackingId": "pid-cross-worktree-smoke-test",
                        "support": {
                            "name": "Synthetic Test",
                            "email": "test@example.invalid",
                            "tier": "Community",
                        },
                        "categories": {"domains": [], "verticals": []},
                    }), encoding="utf-8")
                    subprocess.run(
                        ["git", "init", "--quiet", str(target_root)],
                        check=True,
                    )

                    if mode == "same-root":
                        toolkit = target_root
                        for relative in V31_TOOLKIT_PATHS:
                            destination = toolkit / relative
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(source_root / relative, destination)
                        toolkit_arg = None
                    else:
                        toolkit = source_root
                        toolkit_arg = toolkit
                        self.assertFalse((target_root / "Tools").exists())

                    initialized = initialize_workflow(
                        solution,
                        workflow_profile="authoring",
                        version_bump="none",
                    )
                    for stage in ("discovery", "conversion", "validation"):
                        start_workflow_stage(solution, stage)
                        if stage == "validation":
                            complete_workflow_stage(
                                solution,
                                stage,
                                status="passed",
                                message="Synthetic package smoke; runtime validation not run.",
                                artifacts={"runtimeStatus": "environment-blocked"},
                            )
                        else:
                            complete_workflow_stage(solution, stage, status="passed")

                    args = [
                        "package-v3-1",
                        "--solution", str(solution),
                        "--run-id", initialized["runId"],
                        "--version-bump", "none",
                    ]
                    if toolkit_arg is not None:
                        args.extend(["--toolkit-root", str(toolkit_arg)])
                    with (
                        contextlib.redirect_stdout(io.StringIO()),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        self.assertEqual(0, cli_module.main(args))

                    reports = list(solution.rglob("packaging.v3_1.json"))
                    self.assertEqual(1, len(reports))
                    report = json.loads(reports[0].read_text(encoding="utf-8"))
                    self.assertEqual(str(toolkit.resolve()), report["toolkitRoot"])
                    self.assertEqual(
                        str((toolkit / V31_TOOLKIT_PATHS[0]).resolve()),
                        report["packagerScript"],
                    )
                    for name in (
                        "mainTemplate", "createUiDefinition", "testParameters", "zip",
                    ):
                        artifact = Path(report[name])
                        if not artifact.is_absolute():
                            artifact = solution / artifact
                        self.assertTrue(artifact.is_relative_to(solution), str(artifact))
                        self.assertTrue(artifact.is_file(), str(artifact))
                    if mode == "cross-root":
                        self.assertFalse((target_root / "Tools").exists())

    @mock.patch("sentinel_xdr_migration.packaging.subprocess.run")
    @mock.patch("sentinel_xdr_migration.packaging.shutil.which", return_value="pwsh")
    def test_rejects_incomplete_toolkit_before_invoking_packager(
        self,
        which: mock.Mock,
        run: mock.Mock,
    ) -> None:
        data_file = self.solution / "Data" / "Solution_Sample.json"
        before = json.loads(data_file.read_text(encoding="utf-8"))["Version"]

        with self.assertRaisesRegex(ValueError, "toolkit root is incomplete"):
            package_solution_v3_1(
                self.solution,
                version_bump="minor",
                toolkit_root=self.solution,
            )

        self.assertEqual(before, json.loads(data_file.read_text(encoding="utf-8"))["Version"])
        run.assert_not_called()
        which.assert_not_called()

    def test_input_identity_excludes_generated_outputs_and_tracks_content(self) -> None:
        before = package_input_identity(self.solution)["sha256"]
        (self.solution / "Logs").mkdir()
        (self.solution / "Logs" / "runtime.json").write_text("{}", encoding="utf-8")
        (self.solution / "Package" / "stale.zip").write_text("old", encoding="utf-8")
        self.assertEqual(before, package_input_identity(self.solution)["sha256"])

        detection = self.solution / "XDR Detections" / "Detection.yaml"
        detection.write_text("kind: CustomDetection\nname: changed\n", encoding="utf-8")
        self.assertNotEqual(before, package_input_identity(self.solution)["sha256"])

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

    def test_rejects_local_env_in_any_content_array(self) -> None:
        data = self.solution / "Data" / "Solution_Sample.json"
        document = json.loads(data.read_text())
        document["Playbooks"] = [".env"]
        data.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "local .env configuration"):
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
    def test_rejects_local_env_in_marketplace_zip(self, run, which) -> None:
        run.return_value = CompletedProcess([], 0, "Starting Package Creation using V3.1 tool", "")
        with zipfile.ZipFile(self.solution / "Package" / "1.2.3.zip", "a") as archive:
            archive.writestr("configuration/.env", "PRIVATE_ENV_SENTINEL")
        with self.assertRaisesRegex(RuntimeError, "must not contain local .env"):
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
