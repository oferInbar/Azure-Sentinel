from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .artifacts import existing_artifact_path, existing_artifacts, report_directory, resolve_artifact_reference, portable_artifact, write_json_artifact
from .converter import analytic_rule_files, solution_paths, validate_document
from .content_paths import content_path
from .report_dashboard import render_dashboard

JSON_NAME = "migration-report.json"
HTML_NAME = "migration-report.html"


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    return value if isinstance(value, dict) else {}


def _error(
    stage: str,
    message: Any,
    *,
    provider: str | None = None,
    status_code: Any = None,
    code: Any = None,
    details: Any = None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "provider": provider,
        "statusCode": status_code,
        "code": code,
        "message": str(message),
        "details": details,
    }


def _entity_recommendation(source: dict[str, Any], conversion_notes: list[str]) -> str | None:
    if not any(
        "mapping" in value.lower() or "entity confirmation required" in value.lower()
        for value in conversion_notes
    ):
        return None
    for entity in source.get("entityMappings") or []:
        if entity.get("entityType") != "Account":
            continue
        for field in entity.get("fieldMappings") or []:
            if field.get("identifier") == "Name":
                column = str(field.get("columnName") or "the projected user column")
                return (
                    f"Verify whether `{column}` is always a complete UPN. If confirmed, "
                    f"map it to Account.upnColumn. Otherwise project an Entra user ID, SID, "
                    "or account name plus domain. Do not infer identity semantics from the "
                    "column name alone."
                )
    return None


def build_solution_report(
    solution: str | Path,
    *,
    ingestion_reports: list[str | Path] | None = None,
) -> dict[str, Any]:
    root, analytic, output = solution_paths(solution)
    reports = report_directory(root, create=True)
    manifest = _read_json(existing_artifact_path(root, "manifest.json"))
    workflow = _read_json(existing_artifact_path(root, "workflow-state.json"))
    manifest_by_source = {}
    for item in manifest.get("results") or []:
        reference = str(item.get("sourceRelativePath") or item.get("source") or "").replace("\\", "/")
        root_prefix = root.as_posix() + "/"
        if reference.startswith(root_prefix):
            reference = reference[len(root_prefix):]
        manifest_by_source[reference] = item
    runtime_reports = [
        _read_json(path)
        for path in existing_artifacts(root, "runtime-validation.*.json")
    ]
    deployment = _read_json(existing_artifact_path(root, "deployment.graph.json"))
    analytic_deployment = _read_json(
        existing_artifact_path(root, "deployment.sentinel.json")
    )
    parity = _read_json(existing_artifact_path(root, "alert-parity-report.json"))
    query_parity = _read_json(existing_artifact_path(root, "mock-query-parity.json"))
    deployment_by_id = {
        str(item.get("id")): item for item in deployment.get("results") or []
    }
    analytic_deployment_by_id = {
        str(item.get("id")): item
        for item in analytic_deployment.get("results") or []
    }
    parity_by_detection = {
        str(item.get("detection")).replace("\\", "/"): item for item in parity.get("comparisons") or []
    }
    query_parity_by_detection = {
        str(item.get("detection")).replace("\\", "/"): item
        for item in query_parity.get("comparisons") or []
    }
    ingestion = [
        _read_json(resolve_artifact_reference(root, path))
        for path in ingestion_reports or []
    ]

    rules: list[dict[str, Any]] = []
    for source_path in analytic_rule_files(root):
        source = yaml.safe_load(source_path.read_text(encoding="utf-8-sig")) or {}
        conversion = manifest_by_source.get(source_path.relative_to(root).as_posix()) or {}
        detection_name = source_path.relative_to(analytic).as_posix()
        detection_path = content_path(output, detection_name)
        detection: dict[str, Any] = {}
        structural_errors: list[str] = []
        if detection_path.exists():
            try:
                detection = (
                    yaml.safe_load(detection_path.read_text(encoding="utf-8-sig")) or {}
                )
                structural_errors = validate_document(detection)
            except (OSError, ValueError, yaml.YAMLError) as exc:
                structural_errors = [str(exc)]
        properties = detection.get("properties") or {}
        detection_id = str(properties.get("id") or "")
        analytic_runtime: list[dict[str, Any]] = []
        custom_runtime: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for value in conversion.get("errors") or []:
            errors.append(_error("conversion", value, provider="local-cli"))
        for value in structural_errors:
            errors.append(_error("structural-validation", value, provider="local-cli"))
        for report in runtime_reports:
            provider = str(report.get("provider") or "unknown")
            item = next(
                (
                    candidate
                    for candidate in report.get("results") or []
                    if str(candidate.get("detection") or "").replace("\\", "/") == detection_name
                ),
                None,
            )
            if not item:
                continue
            platform = str(report.get("platform") or "unknown")
            runtime_item = {
                "provider": provider,
                "platform": platform,
                "status": item.get("status"),
                "rowCount": item.get("rowCount"),
            }
            is_sentinel = "Sentinel" in platform
            (analytic_runtime if is_sentinel else custom_runtime).append(runtime_item)
            if item.get("status") in {"failed", "blocked"}:
                errors.append(
                    _error(
                        (
                            "analytic-rule-runtime-validation"
                            if is_sentinel
                            else "custom-detection-runtime-validation"
                        ),
                        item.get("error") or item.get("status"),
                        provider=provider,
                        status_code=item.get("statusCode"),
                        details=item.get("errorDetails"),
                    )
                )
        deployed = deployment_by_id.get(detection_id) or {}
        analytic_deployed = analytic_deployment_by_id.get(str(source.get("id"))) or {}
        if analytic_deployed and not analytic_deployed.get("success"):
            arm_error = analytic_deployed.get("error") or {}
            errors.append(
                _error(
                    "analytic-rule-deployment",
                    arm_error.get("message") or arm_error,
                    provider=str(
                        analytic_deployment.get("provider")
                        or "azure-resource-manager"
                    ),
                    status_code=analytic_deployed.get("statusCode"),
                    code=arm_error.get("code"),
                    details=arm_error,
                )
            )
        if deployed and not deployed.get("success"):
            graph_error = deployed.get("error") or {}
            errors.append(
                _error(
                    "custom-detection-deployment",
                    graph_error.get("message") or graph_error,
                    provider=str(deployment.get("provider") or "microsoft-graph"),
                    status_code=deployed.get("statusCode"),
                    code=graph_error.get("code"),
                    details=graph_error,
                )
            )
        parity_item = parity_by_detection.get(detection_name) or {}
        query_parity_item = query_parity_by_detection.get(detection_name) or {}
        if parity_item and not parity_item.get("passed"):
            errors.append(
                _error(
                    "alert-parity",
                    "Analytic Rule and Custom Detection alerts are not strictly equal",
                    provider="sentinel-and-defender",
                    details=parity_item,
                )
            )
        if query_parity_item and not query_parity_item.get("passed"):
            errors.append(
                _error(
                    "query-result-parity",
                    "Analytic Rule and Custom Detection query results are not equal",
                    provider="sentinel-and-defender",
                    details=query_parity_item,
                )
            )
        conversion_notes = [
            str(value)
            for value in [
                *(conversion.get("errors") or []),
                *(conversion.get("reviewReasons") or []),
            ]
        ]
        rules.append(
            {
                "name": source.get("name") or source_path.stem,
                "sourceFile": str(source_path),
                "sourceSha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "outputFile": str(detection_path),
                "queries": {
                    "source": source.get("query"),
                    "converted": (properties.get("queryCondition") or {}).get("queryText"),
                },
                "attackClassification": {
                    "sourceTactics": source.get("tactics"),
                    "sourceTechniques": source.get("relevantTechniques"),
                    "draftTactics": (
                        (properties.get("detectionAction") or {}).get("alertTemplate") or {}
                    ).get("tactics"),
                    "originalTactics": (
                        (detection.get("contentProvenance") or {}).get("conversion") or {}
                    ).get("originalTactics"),
                    "originalTechniques": (
                        (detection.get("contentProvenance") or {}).get("conversion") or {}
                    ).get("originalTechniques"),
                },
                "analyticRule": {
                    "id": source.get("id"),
                    "sourceStatus": source.get("status"),
                    "deploymentStatus": (
                        "validated-by-alert-parity"
                        if parity_item
                        else analytic_deployed.get("operation") or "not-recorded"
                    ),
                    "alertStatus": (
                        "passed"
                        if parity_item.get("passed")
                        else "failed"
                        if parity_item
                        else "not-run"
                    ),
                    "runtime": analytic_runtime,
                },
                "customDetection": {
                    "id": detection_id or None,
                    "conversionStatus": conversion.get("status") or "not-run",
                    "reviewRequired": bool(conversion.get("reviewRequired")),
                    "reviewReasons": list(conversion.get("reviewReasons") or []),
                    "structuralStatus": (
                        "passed"
                        if detection and not structural_errors
                        else "failed"
                        if detection
                        else "not-generated"
                    ),
                    "deploymentStatus": (
                        deployed.get("operation") or "not-run"
                    ),
                    "runtime": custom_runtime,
                    "alertStatus": (
                        "passed"
                        if parity_item.get("passed")
                        else "failed"
                        if parity_item
                        else "not-run"
                    ),
                },
                "entityRecommendation": _entity_recommendation(
                    source, conversion_notes
                ),
                "queryParity": {
                    "status": (
                        "passed"
                        if query_parity_item.get("passed")
                        else "failed"
                        if query_parity_item
                        else "not-run"
                    ),
                    "matchKey": query_parity_item.get("matchKey"),
                    "analyticRuleRows": query_parity_item.get("analyticRuleRows"),
                    "customDetectionRows": query_parity_item.get(
                        "customDetectionRows"
                    ),
                },
                "warnings": list(conversion.get("warnings") or []),
                "informational": list(
                    conversion.get("informational") or []
                    if "informational" in conversion
                    else (
                        (detection.get("contentProvenance") or {}).get("conversion") or {}
                    ).get("informational") or []
                ),
                "errors": errors,
            }
        )

    report = {
        "solution": root.name,
        "solutionPath": str(root),
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "workflow": {
            "runId": workflow.get("runId"),
            "profile": (workflow.get("context") or {}).get("workflowProfile"),
            "status": workflow.get("workflowStatus"),
            "workspaceConfigured": bool(
                (workflow.get("context") or {}).get("workspaceResourceId")
            ),
            "stages": {
                name: {
                    key: stage.get(key)
                    for key in ("status", "attempts", "message", "evidence", "updatedAt")
                    if stage.get(key) is not None
                }
                for name, stage in (workflow.get("stages") or {}).items()
            },
        },
        "summary": {
            "conversionScope": manifest.get("scope") or {},
            "rules": len(rules),
            "converted": sum(
                item["customDetection"]["conversionStatus"] == "converted"
                for item in rules
            ),
            "needsReview": sum(
                item["customDetection"]["reviewRequired"]
                for item in rules
            ),
            "deploymentReady": sum(
                item["customDetection"]["conversionStatus"] == "converted"
                and not item["customDetection"]["reviewRequired"]
                and item["customDetection"]["structuralStatus"] == "passed"
                for item in rules
            ),
            "strictParityPassed": sum(
                item["customDetection"]["alertStatus"] == "passed" for item in rules
            ),
            "analyticRuntimePassed": sum(
                any(
                    runtime["status"] == "passed"
                    for runtime in item["analyticRule"]["runtime"]
                )
                for item in rules
            ),
            "customRuntimePassed": sum(
                any(
                    runtime["status"] == "passed"
                    for runtime in item["customDetection"]["runtime"]
                )
                for item in rules
            ),
            "queryParityPassed": sum(
                item["queryParity"]["status"] == "passed" for item in rules
            ),
            "errors": sum(len(item["errors"]) for item in rules),
            "informational": sum(len(item["informational"]) for item in rules),
            "rulesWithInformation": sum(bool(item["informational"]) for item in rules),
        },
        "rules": rules,
        "ingestion": ingestion,
        "artifacts": {
            "transformationReport": manifest.get("transformationReport"),
            "runtimeReports": [
                {
                    "provider": item.get("provider"),
                    "jsonReport": item.get("jsonReport"),
                    "htmlReport": item.get("htmlReport"),
                }
                for item in runtime_reports
            ],
            "deploymentReport": deployment.get("reportPath"),
            "analyticDeploymentReport": analytic_deployment.get("reportPath"),
            "queryParityReport": query_parity.get("reportPath"),
            "alertParityReport": parity.get("reportPath"),
            "ingestionReports": [
                item.get("reportPath") for item in ingestion if item.get("reportPath")
            ],
        },
    }
    json_path = reports / JSON_NAME
    html_path = reports / HTML_NAME
    report["jsonReport"] = str(json_path)
    report["htmlReport"] = str(html_path)
    write_json_artifact(root, json_path, report)
    html_path.write_text(render_solution_report(portable_artifact(root, report)), encoding="utf-8", newline="\n")
    return report


def render_solution_report(report: dict[str, Any]) -> str:
    return render_dashboard(report)
