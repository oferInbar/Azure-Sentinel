from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .analytic_rule import analytic_rule_payload
from .artifacts import artifact_path, write_json_artifact
from .arm_client import _arm_request, _arm_token, _sentinel_rule_url
from .converter import analytic_rule_files, solution_paths
from .target_context import require_locked_target


def deploy_analytic_rules(
    solution: str | Path,
    *,
    workspace_resource_id: str | None = None,
) -> dict[str, Any]:
    root, _, output = solution_paths(solution)
    report_path = artifact_path(root, "deployment.sentinel.json", create_parent=True)
    target = require_locked_target(
        root,
        workspace_resource_id=workspace_resource_id,
    )
    workspace_resource_id = target["workspaceResourceId"]
    output.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    source_files = analytic_rule_files(root)
    from .packaging_selection import current_applied_package_selection

    applied_selection = current_applied_package_selection(root)
    if applied_selection is not None:
        selected_paths = {
            str(value).replace("\\", "/").casefold()
            for value in (applied_selection["plan"].get("selection") or {}).get(
                "analyticRules", []
            )
        }
        source_by_path = {
            path.relative_to(root).as_posix().casefold(): path for path in source_files
        }
        if not selected_paths or not selected_paths.issubset(source_by_path):
            raise ValueError("current applied package selection has missing Analytic Rule files")
        source_files = [source_by_path[path] for path in sorted(selected_paths)]
    token = _arm_token()
    for source_path in source_files:
        result: dict[str, Any] = {
            "source": str(source_path),
            "id": None,
            "name": source_path.stem,
            "success": False,
            "operation": "upsert",
            "statusCode": None,
            "error": None,
        }
        try:
            document = yaml.safe_load(source_path.read_text(encoding="utf-8-sig"))
            if not isinstance(document, dict):
                raise ValueError("analytic rule YAML must contain an object")
            rule_id = str(document.get("id") or "")
            result["id"] = rule_id
            result["name"] = str(document.get("name") or source_path.stem)
            payload = analytic_rule_payload(document)
            status, response = _arm_request(
                "PUT",
                _sentinel_rule_url(workspace_resource_id, rule_id),
                token,
                payload,
            )
            result["statusCode"] = status
            result["success"] = status in (200, 201)
            if result["success"]:
                result["enabled"] = bool(
                    (response.get("properties") or {}).get("enabled", False)
                )
                if result["enabled"]:
                    result["success"] = False
                    result["error"] = {
                        "code": "UnexpectedEnabledState",
                        "message": "deployed analytic rule was not disabled",
                        "response": response,
                    }
            else:
                result["error"] = response.get("error") or response
        except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
            result["error"] = {"code": type(exc).__name__, "message": str(exc)}
        results.append(result)

    report = {
        "provider": "azure-resource-manager",
        "workspaceResourceId": workspace_resource_id,
        "target": target,
        "solution": str(root),
        "total": len(results),
        "succeeded": sum(bool(item["success"]) for item in results),
        "failed": sum(not item["success"] for item in results),
        "results": results,
    }
    if applied_selection is not None:
        report["qualificationScope"] = {
            "kind": "applied-package-selection",
            "planSha256": applied_selection["plan"].get("planSha256"),
            "outcome": (applied_selection["plan"].get("summary") or {}).get("outcome"),
            "selectedAnalyticRulePaths": sorted(
                str(value).replace("\\", "/")
                for value in (applied_selection["plan"].get("selection") or {}).get(
                    "analyticRules", []
                )
            ),
            "coverage": applied_selection["plan"].get("summary"),
        }
    report["reportPath"] = str(report_path)
    write_json_artifact(root, report_path, report)
    return report
