from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

from .artifacts import report_directory, repository_root, write_json_artifact, require_solution_conversion_scope
from .content_paths import content_path


PACKAGER_NAME = "V3.1"
DATA_EXCLUSIONS = {
    "parameter.json",
    "parameters.json",
    "system_generated_metadata.json",
    "testparameters.json",
}


def _deployment_parameters(
    template: dict[str, Any], ui: dict[str, Any], test_parameters: dict[str, Any],
    *, has_xdr: bool, contract_path: Path | None = None,
) -> dict[str, bool]:
    contract_path = contract_path or (
        Path(__file__).resolve().parents[2] / "Create-Azure-Sentinel-Solution"
        / "common" / "contentDeploymentParameters.json"
    )
    contract = _read_json(contract_path)
    parameters = template.get("parameters", {})
    if {"E5Flavor", "RegisterE5Content"} & parameters.keys():
        raise RuntimeError("V3.1 package declares obsolete E5 deployment controls; rebuild it.")
    selected = {name: value for name, value in parameters.items() if name.startswith("Deploy")}
    outputs = ui.get("parameters", {}).get("outputs", {})
    controls = {
        element["name"]: element
        for step in ui.get("parameters", {}).get("steps", [])
        if step.get("name") == "contentSelection"
        for element in step.get("elements", [])
    }
    if set(selected) != set(controls) or set(selected) != {
        name for name in outputs if name.startswith("Deploy")
    }:
        raise RuntimeError("V3.1 deployment parameters and UI selections disagree.")
    if test_parameters != parameters:
        raise RuntimeError("V3.1 testParameters.json must match the declared parameter subset.")
    for name, value in selected.items():
        expected = contract.get(name)
        if (
            expected is None or value.get("type") != "bool"
            or value.get("defaultValue") is not expected["defaultValue"]
            or controls[name].get("defaultValue") is not expected["defaultValue"]
            or controls[name].get("type") != "Microsoft.Common.CheckBox"
            or outputs[name] != f"[steps('contentSelection').{name}]"
        ):
            raise RuntimeError(f"Invalid V3.1 content selection contract for {name}.")
    if has_xdr != ("DeployCustomDetection" in selected):
        raise RuntimeError("V3.1 Custom Detection declaration does not match the packaged XDR inputs.")
    return {name: value["defaultValue"] for name, value in selected.items()}


def _solution_data_file(data_directory: Path) -> Path:
    candidates = sorted(
        path
        for path in data_directory.glob("*.json")
        if path.name.lower() not in DATA_EXCLUSIONS
    )
    if len(candidates) != 1:
        raise ValueError(
            f"expected exactly one solution data JSON in {data_directory}, "
            f"found {len(candidates)}"
        )
    return candidates[0]


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON file must contain an object: {path}")
    return value


def _value(document: dict[str, Any], name: str) -> Any:
    for key, value in document.items():
        if key.lower() == name.lower():
            return value
    return None


def _xdr_references(solution: Path, document: dict[str, Any]) -> list[Path]:
    values = _value(document, "XDR Detections")
    if values is None:
        values = _value(document, "Custom Detections")
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError("solution data XDR Detections must be an array")

    references: list[Path] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("solution data contains an invalid XDR Detection reference")
        normalized = value.replace("\\", "/")
        if not normalized.startswith("XDR Detections/"):
            raise ValueError("XDR references must be under XDR Detections, never Logs or Reports")
        candidate = content_path(solution, normalized)
        if not candidate.is_file():
            raise ValueError(f"referenced XDR Detection does not exist: {candidate}")
        references.append(candidate.resolve())
    return references


def package_solution_v3_1(
    solution: str | Path,
    *,
    version_bump: str,
) -> dict[str, Any]:
    if version_bump not in {"none", "patch", "minor", "major"}:
        raise ValueError("version bump must be none, patch, minor, or major")

    root = Path(solution).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"solution folder does not exist: {root}")
    require_solution_conversion_scope(root)
    reports = report_directory(root, create=True)
    data_directory = root / "Data"
    if not data_directory.is_dir():
        raise ValueError(f"solution data folder does not exist: {data_directory}")

    data_file = _solution_data_file(data_directory)
    before = _read_json(data_file)
    for values in before.values():
        if isinstance(values, list):
            for value in values:
                if isinstance(value, str) and any(
                    part.lower() in {"logs", "reports", "evidence"}
                    for part in value.replace("\\", "/").split("/")
                ):
                    raise ValueError("solution Data content arrays must never include Logs, Reports or Evidence")
    xdr_files = _xdr_references(root, before)
    repository = repository_root(root)
    script = (
        repository
        / "Tools"
        / "Create-Azure-Sentinel-Solution"
        / "V3"
        / "createSolutionV3_1.ps1"
    )
    if not script.is_file():
        raise ValueError(f"V3.1 solution packager does not exist: {script}")
    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise RuntimeError("PowerShell 7 is required to run the V3.1 solution packager.")

    command = [
        pwsh,
        "-NoProfile",
        "-File",
        str(script),
        "-SolutionDataFolderPath",
        str(data_directory),
        "-VersionMode",
        "local",
        "-VersionBump",
        version_bump,
    ]
    completed = subprocess.run(
        command,
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    output = "\n".join(
        value.strip() for value in (completed.stdout, completed.stderr) if value.strip()
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"V3.1 solution packaging failed with exit code {completed.returncode}: "
            f"{output[-4000:]}"
        )
    if "Starting Package Creation using V3.1 tool" not in output:
        raise RuntimeError("Packaging output did not confirm the V3.1 entry point.")
    warnings = [
        line for line in output.splitlines()
        if any(label in line for label in (
            "CUSTOMER USAGE ATTRIBUTION:", "V3.1 CONTENT SELECTION:", "V3.1 TACTIC SELECTION:",
        ))
    ]
    for warning in warnings:
        print(warning, file=sys.stderr)
    attribution_sources = [
        line for line in output.splitlines() if "CUSTOMER USAGE ATTRIBUTION SOURCE:" in line
    ]
    for source in attribution_sources:
        print(source, file=sys.stderr)

    after = _read_json(data_file)
    version = str(_value(after, "Version") or "").strip()
    if not version:
        raise ValueError(f"solution data does not declare a package version: {data_file}")

    package = root / "Package"
    main_template = package / "mainTemplate.json"
    create_ui = package / "createUiDefinition.json"
    test_parameters = package / "testParameters.json"
    zip_path = package / f"{version}.zip"
    required = (main_template, create_ui, test_parameters, zip_path)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            "V3.1 packaging completed without required artifacts: " + ", ".join(missing)
        )
    deployment_parameters = _deployment_parameters(
        _read_json(main_template), _read_json(create_ui), _read_json(test_parameters),
        has_xdr=bool(xdr_files),
        contract_path=script.parent.parent / "common" / "contentDeploymentParameters.json",
    )
    try:
        with zipfile.ZipFile(zip_path) as archive:
            names = {Path(name).name for name in archive.namelist()}
            if any(
                part.lower() in {"logs", "reports", "evidence"}
                for name in archive.namelist()
                for part in name.replace("\\", "/").split("/")
            ):
                raise RuntimeError("generated package ZIP must not contain Logs, Reports or Evidence")
    except (OSError, zipfile.BadZipFile) as exc:
        raise RuntimeError(f"generated package ZIP is invalid: {zip_path}: {exc}") from exc
    missing_entries = {"mainTemplate.json", "createUiDefinition.json"} - names
    if missing_entries:
        raise RuntimeError(
            "generated package ZIP is missing: " + ", ".join(sorted(missing_entries))
        )

    reports = report_directory(root, create=True)
    report_path = reports / "packaging.v3_1.json"
    result = {
        "status": "passed",
        "packager": PACKAGER_NAME,
        "warnings": warnings,
        "attributionSources": attribution_sources,
        "solution": str(root),
        "version": version,
        "versionBump": version_bump,
        "solutionData": str(data_file),
        "xdrDetectionCount": len(xdr_files),
        "deploymentParameters": deployment_parameters,
        "customDetectionRegistrationSupport": "unverified" if xdr_files else "notApplicable",
        "mainTemplate": str(main_template),
        "createUiDefinition": str(create_ui),
        "testParameters": str(test_parameters),
        "zip": str(zip_path),
        "packageReport": str(report_path),
        "workflowArtifacts": {
            "packager": PACKAGER_NAME,
            "packageReport": str(report_path),
            "mainTemplate": str(main_template),
            "createUiDefinition": str(create_ui),
            "testParameters": str(test_parameters),
            "zip": str(zip_path),
        },
    }
    write_json_artifact(root, report_path, result)
    return result
