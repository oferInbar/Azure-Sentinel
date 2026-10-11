from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import artifact_path, write_json_artifact
from .workflow import workflow_status

EXCEPTION_ID = "ciscoasa-3.1.0-arm-package-acceptance"
EXPECTED_TEMPLATE_SHA256 = (
    "74f702b16cf395425a66cd9d98b484a2f2c5f46f9395e39fcaceb542cd8094b8"
)
APPROVED_TARGET = {
    "tenantId": "9ad27f02-5ed8-490a-8113-8ff847030e0a",
    "subscriptionId": "a718424a-41c0-432d-a17b-38af96331f5c",
    "resourceGroup": "ContentCreation",
    "workspaceResourceId": (
        "/subscriptions/a718424a-41c0-432d-a17b-38af96331f5c/"
        "resourceGroups/ContentCreation/providers/"
        "Microsoft.OperationalInsights/workspaces/ContentTestCreation"
    ),
    "workspaceCustomerId": "906212d4-cf6f-4086-ac72-e884b1b41850",
    "environment": "approved non-production lab",
}
APPROVAL_FILE = "package-acceptance.approval.json"
VALIDATION_FILE = "package-acceptance.arm-validation.json"
DEPLOYMENT_FILE = "package-acceptance.arm-deployment.json"
LOCAL_APPROVAL_TEXT = (
    "I approve the scoped CiscoASA 3.1.0 ARM package-acceptance tests; "
    "failed and skipped local checks remain failed and skipped."
)
FINAL_APPROVAL_PREFIX = (
    "I approve resource writes for CiscoASA 3.1.0 ARM package acceptance "
    "to the exact recorded ContentCreation / ContentTestCreation lab target, "
    "including Custom Detection installation and Content Hub registration."
)
PARAMETER_CONFIGURATIONS = (
    {
        "name": "sentinel-content",
        "parameters": {
            "DeployAnalyticsRule": True,
            "DeployPlaybook": True,
            "DeployWorkbook": True,
            "DeployDataConnector": True,
            "DeployCustomDetection": False,
        },
    },
    {
        "name": "custom-detections-only",
        "parameters": {
            "DeployAnalyticsRule": False,
            "DeployPlaybook": False,
            "DeployWorkbook": False,
            "DeployDataConnector": False,
            "DeployCustomDetection": True,
        },
    },
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _solution_files(solution: str | Path) -> tuple[Path, Path]:
    root = Path(solution).expanduser().resolve()
    if root.name != "CiscoASA" or root.parent.name != "Solutions":
        raise ValueError("this exception is limited to Solutions/CiscoASA")
    template = root / "Package" / "mainTemplate.json"
    if not template.is_file():
        raise ValueError(f"package template does not exist: {template}")
    actual_hash = _sha256(template)
    if actual_hash != EXPECTED_TEMPLATE_SHA256:
        raise ValueError(
            "CiscoASA package template hash does not match the explicitly "
            f"approved package: expected {EXPECTED_TEMPLATE_SHA256}, got {actual_hash}"
        )
    try:
        document = json.loads(template.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"package template is invalid: {template}: {exc}") from exc
    if document.get("variables", {}).get("_solutionVersion") != "3.1.0":
        raise ValueError("the scoped exception only supports CiscoASA version 3.1.0")
    _verify_custom_detection_resources(document)
    return root, template


def _verify_custom_detection_resources(template: dict[str, Any]) -> None:
    installs: list[dict[str, Any]] = []
    registrations: list[dict[str, Any]] = []

    def visit(resources: list[dict[str, Any]]) -> None:
        for resource in resources:
            resource_type = str(resource.get("type", "")).lower()
            if resource_type.startswith("microsoft.security/detectionrules"):
                installs.append(resource)
            properties = resource.get("properties") or {}
            if (
                resource_type
                == "microsoft.operationalinsights/workspaces/providers/contenttemplates"
                and properties.get("contentKind") == "CustomDetection"
            ):
                registrations.append(resource)
            nested = properties.get("template")
            if isinstance(nested, dict):
                visit(nested.get("resources") or [])
            visit(resource.get("resources") or [])

    visit(template.get("resources") or [])
    if len(installs) != 3 or len(registrations) != 3:
        raise ValueError(
            "CiscoASA package acceptance requires exactly three Custom Detection "
            f"installs and three registrations; found {len(installs)} and "
            f"{len(registrations)}"
        )
    for resource in installs:
        status = (resource.get("properties") or {}).get("status")
        if status != "disabled":
            raise ValueError(
                "every packaged Custom Detection install must remain disabled"
            )


def _assert_recorded_target(state: dict[str, Any]) -> None:
    context = state.get("context") or {}
    expected_context = {
        "tenantId": APPROVED_TARGET["tenantId"],
        "subscriptionId": APPROVED_TARGET["subscriptionId"],
        "workspaceResourceId": APPROVED_TARGET["workspaceResourceId"],
        "workspaceCustomerId": APPROVED_TARGET["workspaceCustomerId"],
    }
    mismatches = [
        f"{key}={context.get(key)!r} (expected {value!r})"
        for key, value in expected_context.items()
        if context.get(key) != value
    ]
    if mismatches:
        raise ValueError(
            "workflow target does not match the approved lab target: "
            + "; ".join(mismatches)
        )


def _approval_path(solution: str | Path) -> Path:
    return artifact_path(solution, APPROVAL_FILE)


def approve_package_acceptance(
    solution: str | Path,
    *,
    approver: str,
    approval_text: str,
) -> dict[str, Any]:
    root, template = _solution_files(solution)
    if approval_text.strip() != LOCAL_APPROVAL_TEXT:
        raise ValueError(
            "approval text must exactly acknowledge this scoped package test "
            "and preserve failed/skipped local checks"
        )
    if not approver.strip():
        raise ValueError("approver must be a non-empty name or approval reference")

    state = workflow_status(root)
    _assert_recorded_target(state)
    stages = state["stages"]
    if state["context"].get("workflowProfile") != "authoring":
        raise ValueError("this exception only applies to the existing Authoring run")
    if any(stages[name]["status"] != "passed" for name in ("discovery", "conversion", "validation")):
        raise ValueError("discovery, conversion, and validation must remain passed")
    if stages["packaging"]["status"] != "failed":
        raise ValueError(
            "the scoped exception only applies to the existing failed packaging stage"
        )
    package_report_value = stages["packaging"]["artifacts"].get("packageReport")
    if not package_report_value:
        raise ValueError("failed packaging stage has no canonical V3.1 package report")
    package_report = Path(package_report_value)
    if not package_report.is_absolute():
        package_report = root / package_report
    if not package_report.is_file():
        raise ValueError(f"canonical package report is missing: {package_report}")
    report = json.loads(package_report.read_text(encoding="utf-8-sig"))
    if report.get("status") != "passed" or report.get("version") != "3.1.0":
        raise ValueError("canonical V3.1 package report does not prove version 3.1.0")

    log_reference = stages["packaging"]["artifacts"].get("localValidationLog")
    local_validation_log = Path(log_reference) if log_reference else None
    if local_validation_log and not local_validation_log.is_absolute():
        local_validation_log = root / local_validation_log
    if not local_validation_log or not local_validation_log.is_file():
        raise ValueError("the failed local-validation transcript is missing")
    destination = _approval_path(root)
    if destination.exists():
        raise ValueError(
            f"package acceptance approval already exists and will not be overwritten: {destination}"
        )

    record = {
        "schemaVersion": "1.0.0",
        "exceptionId": EXCEPTION_ID,
        "status": "authorized-for-read-only-arm-validation",
        "approval": {
            "approver": approver.strip(),
            "approvedAt": _utc_now(),
            "statement": approval_text.strip(),
            "scope": "read-only ARM validation for the two fixed parameter configurations",
        },
        "solution": "CiscoASA",
        "packageVersion": "3.1.0",
        "packageTemplate": "Package/mainTemplate.json",
        "packageTemplateSha256": _sha256(template),
        "target": deepcopy(APPROVED_TARGET),
        "runId": state.get("runId"),
        "workflowProfile": state["context"]["workflowProfile"],
        "localChecks": {
            "workflowPackagingStatus": stages["packaging"]["status"],
            "workflowPackagingMessage": stages["packaging"]["message"],
            "workflowPackagingArtifacts": deepcopy(stages["packaging"]["artifacts"]),
            "workflowStatePath": state["statePath"],
            "workflowStateStatus": state["workflowStatus"],
            "localValidationTranscript": str(local_validation_log),
            "localValidationTranscriptSha256": _sha256(local_validation_log),
            "interpretation": (
                "Failed and skipped local checks are retained as-is; this approval "
                "does not waive, rerun, or mark them passed."
            ),
        },
        "parameterConfigurations": deepcopy(PARAMETER_CONFIGURATIONS),
        "armValidationStatus": "not-run",
        "resourceWriteApproval": "not-granted",
        "liveRegistrationSupport": "unverified",
        "alertParity": "not-tested",
    }
    write_json_artifact(root, destination, record)
    return {**record, "approvalPath": str(destination)}


def _load_approval(root: Path, template: Path) -> tuple[Path, dict[str, Any]]:
    path = _approval_path(root)
    if not path.is_file():
        raise ValueError(
            "scoped package acceptance approval is missing; record the explicit "
            "approval before ARM validation"
        )
    record = json.loads(path.read_text(encoding="utf-8-sig"))
    if (
        record.get("exceptionId") != EXCEPTION_ID
        or record.get("packageTemplateSha256") != _sha256(template)
        or record.get("target") != APPROVED_TARGET
    ):
        raise ValueError(
            "package approval does not match the current package, target, or validation state"
        )
    return path, record


def _run_az(args: list[str]) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("az")
    if not executable:
        raise RuntimeError("Azure CLI is required for package acceptance ARM tests")
    return subprocess.run(
        [executable, *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _run_json_command(args: list[str]) -> dict[str, Any]:
    result = _run_az(args)
    if result.returncode:
        raise RuntimeError(
            f"Azure CLI command failed ({result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Azure CLI returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Azure CLI response must be a JSON object")
    return value


def _resolve_exact_workspace() -> dict[str, str]:
    account = _run_json_command(
        [
            "account",
            "show",
            "--subscription",
            APPROVED_TARGET["subscriptionId"],
            "--output",
            "json",
        ]
    )
    if str(account.get("tenantId", "")).lower() != APPROVED_TARGET["tenantId"].lower():
        raise ValueError("the active Azure CLI tenant does not match the approved tenant")
    workspace = _run_json_command(
        [
            "monitor",
            "log-analytics",
            "workspace",
            "show",
            "--ids",
            APPROVED_TARGET["workspaceResourceId"],
            "--subscription",
            APPROVED_TARGET["subscriptionId"],
            "--output",
            "json",
        ]
    )
    exact_values = {
        "id": APPROVED_TARGET["workspaceResourceId"],
        "customerId": APPROVED_TARGET["workspaceCustomerId"],
        "name": "ContentTestCreation",
        "resourceGroup": APPROVED_TARGET["resourceGroup"],
    }
    for key, expected in exact_values.items():
        if str(workspace.get(key, "")).lower() != expected.lower():
            raise ValueError(
                f"workspace preflight mismatch for {key}: "
                f"{workspace.get(key)!r} != {expected!r}"
            )
    location = workspace.get("location")
    if not isinstance(location, str) or not location.strip():
        raise ValueError("exact workspace preflight did not return its location")
    return {
        "name": "ContentTestCreation",
        "resourceGroup": APPROVED_TARGET["resourceGroup"],
        "location": location,
        "resourceId": APPROVED_TARGET["workspaceResourceId"],
        "customerId": APPROVED_TARGET["workspaceCustomerId"],
    }


def _parameter_args(config: dict[str, Any], workspace: dict[str, str]) -> list[str]:
    values = [
        f"workspace={workspace['name']}",
        f"workspace-location={workspace['location']}",
    ]
    values.extend(
        f"{key}={'true' if enabled else 'false'}"
        for key, enabled in config["parameters"].items()
    )
    return values


def _validate_configuration(
    template: Path,
    workspace: dict[str, str],
    config: dict[str, Any],
) -> dict[str, Any]:
    args = [
        "deployment",
        "group",
        "validate",
        "--subscription",
        APPROVED_TARGET["subscriptionId"],
        "--resource-group",
        APPROVED_TARGET["resourceGroup"],
        "--name",
        f"ciscoasa-3-1-0-{config['name']}-preflight",
        "--template-file",
        str(template),
        "--parameters",
        *_parameter_args(config, workspace),
        "--output",
        "json",
    ]
    result = _run_az(args)
    response: dict[str, Any] | None = None
    if result.stdout.strip():
        try:
            parsed = json.loads(result.stdout)
            response = parsed if isinstance(parsed, dict) else {"value": parsed}
        except json.JSONDecodeError:
            response = {"output": result.stdout[-4000:]}
    success = result.returncode == 0 and not (
        response and response.get("error")
    )
    return {
        "configuration": config["name"],
        "parameters": {
            "workspace": workspace["name"],
            "workspace-location": workspace["location"],
            **config["parameters"],
        },
        "status": "passed" if success else "failed",
        "armValidationOnly": True,
        "resourceWrites": False,
        "exitCode": result.returncode,
        "response": response,
        "stderr": result.stderr[-4000:] if result.stderr else None,
    }


def validate_package_acceptance(solution: str | Path) -> dict[str, Any]:
    root, template = _solution_files(solution)
    approval_path, approval = _load_approval(root, template)
    if approval.get("armValidationStatus") not in {"not-run", "failed"}:
        raise ValueError(
            "ARM validation has already passed; preserve that result instead of rerunning it"
        )
    workspace = _resolve_exact_workspace()
    results = [
        _validate_configuration(template, workspace, config)
        for config in PARAMETER_CONFIGURATIONS
    ]
    success = all(item["status"] == "passed" for item in results)
    report = {
        "schemaVersion": "1.0.0",
        "exceptionId": EXCEPTION_ID,
        "status": "passed" if success else "failed",
        "meaning": (
            "ARM template validation only; this is not a deployment, provider "
            "registration test, workflow packaging pass, or alert-parity result."
        ),
        "solution": "CiscoASA",
        "packageVersion": "3.1.0",
        "packageTemplateSha256": _sha256(template),
        "target": deepcopy(APPROVED_TARGET),
        "resolvedWorkspace": workspace,
        "approvalPath": str(approval_path),
        "approval": approval["approval"],
        "configurations": results,
        "liveRegistrationSupport": "unverified",
        "alertParity": "not-tested",
        "timestamp": _utc_now(),
    }
    report_path = artifact_path(root, VALIDATION_FILE, create_parent=True)
    write_json_artifact(root, report_path, report)
    approval["armValidationStatus"] = report["status"]
    approval["armValidationReport"] = str(report_path)
    write_json_artifact(root, approval_path, approval)
    return {**report, "reportPath": str(report_path)}


def deploy_package_acceptance(
    solution: str | Path,
    *,
    final_approval: str,
) -> dict[str, Any]:
    root, template = _solution_files(solution)
    approval_path, approval = _load_approval(root, template)
    if final_approval.strip() != FINAL_APPROVAL_PREFIX:
        raise ValueError(
            "final resource-write approval must explicitly name the exact lab "
            "scope and Custom Detection installation plus registration"
        )
    if approval.get("armValidationStatus") != "passed":
        raise ValueError("matching successful ARM validation is required before resource writes")
    validation_path = artifact_path(root, VALIDATION_FILE)
    if not validation_path.is_file():
        raise ValueError("both approved ARM validations must pass before resource writes")
    validation = json.loads(validation_path.read_text(encoding="utf-8-sig"))
    if (
        validation.get("status") != "passed"
        or validation.get("packageTemplateSha256") != _sha256(template)
        or validation.get("target") != APPROVED_TARGET
        or len(validation.get("configurations") or []) != len(PARAMETER_CONFIGURATIONS)
        or any(item.get("status") != "passed" for item in validation["configurations"])
    ):
        raise ValueError("matching successful ARM validation is required before writes")

    workspace = validation["resolvedWorkspace"]
    report_path = artifact_path(root, DEPLOYMENT_FILE, create_parent=True)
    report: dict[str, Any] = {
        "schemaVersion": "1.0.0",
        "exceptionId": EXCEPTION_ID,
        "status": "approved-not-started",
        "solution": "CiscoASA",
        "packageVersion": "3.1.0",
        "packageTemplateSha256": _sha256(template),
        "target": deepcopy(APPROVED_TARGET),
        "finalResourceWriteApproval": {
            "statement": final_approval.strip(),
            "approvedAt": _utc_now(),
        },
        "validationReport": str(validation_path),
        "operations": [],
        "liveRegistrationSupport": "unverified",
        "alertParity": "not-tested",
    }
    write_json_artifact(root, report_path, report)
    approval["resourceWriteApproval"] = {
        "status": "granted-for-this-invocation",
        "statement": final_approval.strip(),
        "approvedAt": report["finalResourceWriteApproval"]["approvedAt"],
        "deploymentReport": str(report_path),
    }
    write_json_artifact(root, approval_path, approval)

    for config in PARAMETER_CONFIGURATIONS:
        args = [
            "deployment",
            "group",
            "create",
            "--subscription",
            APPROVED_TARGET["subscriptionId"],
            "--resource-group",
            APPROVED_TARGET["resourceGroup"],
            "--name",
            f"ciscoasa-3-1-0-{config['name']}-acceptance",
            "--template-file",
            str(template),
            "--parameters",
            *_parameter_args(config, workspace),
            "--output",
            "json",
        ]
        result = _run_az(args)
        response: dict[str, Any] | None = None
        if result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
                response = parsed if isinstance(parsed, dict) else {"value": parsed}
            except json.JSONDecodeError:
                response = {"output": result.stdout[-4000:]}
        success = result.returncode == 0 and not (
            response and response.get("error")
        )
        report["operations"].append(
            {
                "configuration": config["name"],
                "status": "accepted" if success else "failed",
                "exitCode": result.returncode,
                "response": response,
                "stderr": result.stderr[-4000:] if result.stderr else None,
            }
        )
        report["status"] = (
            "accepted"
            if len(report["operations"]) == len(PARAMETER_CONFIGURATIONS)
            and all(item["status"] == "accepted" for item in report["operations"])
            else "failed"
            if not success
            else "partially-accepted"
        )
        report["updatedAt"] = _utc_now()
        write_json_artifact(root, report_path, report)
        if not success:
            break
    return {**report, "reportPath": str(report_path)}
