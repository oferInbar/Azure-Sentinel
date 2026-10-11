"""Build a no-write ingestion-contract plan for a complete solution rule inventory."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INGESTION_TOOL_ROOT = REPOSITORY_ROOT / "Tools" / "AzureMonitorLogsIngestion"
if str(INGESTION_TOOL_ROOT) not in sys.path:
    sys.path.insert(0, str(INGESTION_TOOL_ROOT))

from azure_monitor_logs_ingestion.registry import (  # noqa: E402
    DEFAULT_REGISTRY,
    find_capability,
    resolve_contract,
)

SOLUTION_GENERATOR_ROOT = REPOSITORY_ROOT / "Tools" / "SolutionMigration"
if str(SOLUTION_GENERATOR_ROOT) not in sys.path:
    sys.path.insert(0, str(SOLUTION_GENERATOR_ROOT))

import generate_mock_scenario as scenario  # noqa: E402

TARGET_FIELDS = (
    "tenantId",
    "subscriptionId",
    "workspaceResourceId",
    "workspaceCustomerId",
)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_hash(value: Any) -> str:
    return _sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
    )


def _load_target(path: str | Path) -> dict[str, str]:
    target_path = Path(path)
    value = json.loads(target_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("qualification target context must be a JSON object")
    target = {field: str(value.get(field, "")).strip() for field in TARGET_FIELDS}
    if any(not item for item in target.values()):
        raise ValueError(
            "qualification target context must contain tenantId, subscriptionId, "
            "workspaceResourceId, and workspaceCustomerId"
        )
    workspace = target["workspaceResourceId"]
    if not workspace.lower().startswith(
        "/subscriptions/" + target["subscriptionId"].lower() + "/"
    ):
        raise ValueError(
            "qualification workspace ARM ID does not match its subscriptionId"
        )
    if not re.fullmatch(
        r"/subscriptions/[^/]+/resourceGroups/[^/]+/"
        r"providers/Microsoft\.OperationalInsights/workspaces/[^/]+",
        workspace,
        re.I,
    ):
        raise ValueError("qualification workspaceResourceId is not an exact workspace ARM ID")
    return target


def _rule_files(solution_root: Path) -> list[Path]:
    paths: list[Path] = []
    for folder_name in ("Analytic Rules", "Analytics Rules"):
        folder = solution_root / folder_name
        if folder.exists():
            paths.extend(scenario._content_yaml_files(folder))
    return sorted(set(paths), key=lambda item: item.relative_to(solution_root).as_posix())


def _matching_detection(
    solution_root: Path, source_rule: dict
) -> tuple[Path | None, dict | None, str | None]:
    folder = solution_root / "XDR Detections"
    if not folder.is_dir():
        return None, None, "Converted Custom Detection folder is missing."
    source_id = str(source_rule.get("id") or "")
    if not source_id:
        return None, None, "Source rule has no stable ID for AR/CD pairing."
    matches: list[tuple[Path, dict]] = []
    for path in scenario._content_yaml_files(folder):
        if path.name.lower() in {"migration-config.yaml", "migration-config.yml"}:
            continue
        document = scenario._load_yaml(path)
        if scenario._detection_source_id(document) == source_id:
            matches.append((path, document))
    if len(matches) != 1:
        reason = (
            "No converted Custom Detection matches the source rule."
            if not matches
            else "Multiple converted Custom Detections match the source rule."
        )
        return None, None, reason
    return matches[0][0], matches[0][1], None


def _source_tables(query: str, registry_path: str | Path) -> list[str]:
    registry = yaml.safe_load(Path(registry_path).read_text(encoding="utf-8"))
    tables = [
        str(item["table"])
        for item in registry.get("tables", [])
        if isinstance(item, dict) and item.get("table")
    ]
    return [
        table
        for table in tables
        if re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(table) + r"(?![A-Za-z0-9_])",
            query,
            re.I,
        )
    ]


def _rule_plan(
    solution_root: Path,
    path: Path,
    document: dict | None,
    parse_error: str | None,
    registry_path: str | Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    relative_path = path.relative_to(solution_root).as_posix()
    file_hash = _sha256(path.read_bytes())
    result: dict[str, Any] = {
        "sourcePath": relative_path,
        "sourceFileSha256": file_hash,
        "ruleId": (document or {}).get("id"),
        "ruleName": (document or {}).get("name"),
        "status": "blocked",
        "blockers": [],
    }
    if parse_error:
        result["blockers"].append(parse_error)
        return result, {}
    try:
        source_query = scenario._query(document)
        source_query_hash = _sha256(source_query.encode("utf-8"))
        result["sourceQuerySha256"] = source_query_hash
        target_query = ""
        detection_path, detection, detection_error = _matching_detection(
            solution_root, document
        )
        if detection_error:
            result["blockers"].append(detection_error)
        else:
            target_query = scenario._query(detection)
            result["customDetectionPath"] = detection_path.relative_to(
                solution_root
            ).as_posix()
            result["customDetectionFileSha256"] = _sha256(
                detection_path.read_bytes()
            )
            result["customDetectionQuerySha256"] = _sha256(
                target_query.encode("utf-8")
            )

        source_tables = _source_tables(source_query, registry_path)
        direct_source = scenario._first_query_source(source_query)
        if len(source_tables) > 1:
            result["blockers"].append(
                "Source query does not resolve to exactly one registered table; "
                "review multi-table or unresolved KQL manually."
            )
            return result, {}
        table = source_tables[0] if source_tables else direct_source
        if not table:
            result["blockers"].append(
                "Source table could not be resolved from the existing query lineage."
            )
            return result, {}
        target_tables = _source_tables(target_query, registry_path) if target_query else []
        if target_query and (
            len(target_tables) != 1
            or target_tables[0].casefold() != table.casefold()
        ):
            result["blockers"].append(
                "AR and CD queries do not resolve to the same single registered source table."
            )
        result["sourceTable"] = table
        capability = find_capability(table, registry_path)
        if not capability:
            result["blockers"].append(
                f"No reviewed ingestion contract is registered for {table!r}."
            )
            return result, {}
        contract = scenario._load_yaml(capability.contract_path)
        output_columns = {
            str(item["name"]): str(item["type"])
            for item in (contract.get("destination") or {}).get("columns") or []
            if isinstance(item, dict) and item.get("name") and item.get("type")
        }
        if not output_columns:
            output_columns = {
                str(item["name"]): str(item["type"])
                for item in contract.get("inputColumns") or []
                if isinstance(item, dict) and item.get("name") and item.get("type")
            }
        combined_query = source_query + "\n" + target_query
        required_fields = scenario._query_fields_from_schema(combined_query, output_columns)
        predicate_fields, unresolved_aliases = scenario._query_predicate_fields(
            combined_query,
            output_columns,
        )
        for name, kind in predicate_fields.items():
            if name.casefold() not in {
                field.casefold() for field in required_fields
            }:
                required_fields[name] = kind
        resolution = resolve_contract(
            table,
            required_fields,
            registry_path=registry_path,
        )
        if unresolved_aliases:
            resolution["blockers"] = list(resolution.get("blockers") or []) + [
                f"Decisive predicate field {name!r} is a query alias and cannot be "
                "mapped to a source field safely."
                for name in unresolved_aliases
            ]
            resolution["status"] = "blocked"
        result["requiredSourceFields"] = required_fields
        result["contractResolution"] = {
            "status": resolution["status"],
            "schemaFingerprint": resolution.get("schemaFingerprint"),
            "transformFingerprint": resolution.get("transformFingerprint"),
            "liveValidated": resolution.get("liveValidated"),
            "references": resolution.get("references"),
            "blockers": resolution.get("blockers", []),
        }
        assessment = scenario.assess_query(
            source_query, document if isinstance(document, dict) else {}
        )
        result["queryAssessment"] = assessment
        blockers = list(result["blockers"])
        blockers.extend(resolution.get("blockers") or [])
        if assessment.get("status") != "simple":
            blockers.append(
                "Scenario behavior requires reviewed fixture generation: "
                + "; ".join(assessment.get("reasons") or [assessment.get("status", "review")])
            )
        if target_query:
            detection_assessment = scenario.assess_query(
                target_query, document if isinstance(document, dict) else {}
            )
            result["customDetectionQueryAssessment"] = detection_assessment
            if detection_assessment.get("status") != "simple":
                blockers.append(
                    "Converted Custom Detection requires reviewed fixture generation: "
                    + "; ".join(
                        detection_assessment.get("reasons")
                        or [detection_assessment.get("status", "review")]
                    )
                )
        result["blockers"] = blockers
        result["status"] = (
            "ready-for-fixture-review"
            if not blockers and resolution["status"] == "provisioning-plan"
            else "manual-review-required"
        )
        groups: dict[str, dict[str, Any]] = {}
        if resolution["status"] == "provisioning-plan":
            identity = _canonical_hash(
                {
                    "table": table,
                    "schemaFingerprint": resolution["schemaFingerprint"],
                    "transformFingerprint": resolution["transformFingerprint"],
                }
            )
            groups[identity] = {
                "table": table,
                "schemaFingerprint": resolution["schemaFingerprint"],
                "transformFingerprint": resolution["transformFingerprint"],
                "route": resolution["route"],
                "outputStream": resolution["outputStream"],
                "contractPath": capability.contract_path.relative_to(
                    Path(registry_path).resolve().parent
                ).as_posix(),
                "ruleIds": [result.get("ruleId")],
            }
        return result, groups
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        result["blockers"].append(str(exc))
        return result, {}


def build_plan(
    solution_root: str | Path,
    target_context: dict[str, str],
    *,
    registry_path: str | Path = DEFAULT_REGISTRY,
    expected_inventory_sha256: str | None = None,
    expected_target_sha256: str | None = None,
) -> dict[str, Any]:
    root = Path(solution_root).resolve()
    if not root.is_dir():
        raise ValueError(f"solution folder does not exist: {root}")
    rule_paths = _rule_files(root)
    if not rule_paths:
        raise ValueError(f"no recursive Analytic Rule YAML files found under {root}")

    rules: list[dict[str, Any]] = []
    grouped: dict[str, dict[str, Any]] = {}
    inventory_material: list[dict[str, str]] = []
    seen_ids: dict[str, str] = {}
    for path in rule_paths:
        try:
            document = scenario._load_yaml(path)
            parse_error = None
        except (OSError, ValueError, RuntimeError) as exc:
            document = None
            parse_error = str(exc)
        rule_result, groups = _rule_plan(
            root, path, document, parse_error, registry_path
        )
        rule_id = str(rule_result.get("ruleId") or "")
        if rule_id and rule_id in seen_ids:
            rule_result["blockers"].append(
                f"Duplicate source rule ID also appears in {seen_ids[rule_id]}."
            )
            rule_result["status"] = "blocked"
            groups = {}
        elif rule_id:
            seen_ids[rule_id] = rule_result["sourcePath"]
        rules.append(rule_result)
        inventory_material.append(
            {
                "sourcePath": rule_result["sourcePath"],
                "sourceFileSha256": rule_result["sourceFileSha256"],
                "sourceQuerySha256": rule_result.get("sourceQuerySha256", ""),
                "customDetectionFileSha256": rule_result.get(
                    "customDetectionFileSha256", ""
                ),
                "customDetectionQuerySha256": rule_result.get(
                    "customDetectionQuerySha256", ""
                ),
                "ruleId": rule_id,
            }
        )
        for identity, group in groups.items():
            if identity not in grouped:
                grouped[identity] = group
            else:
                grouped[identity]["ruleIds"].append(rule_result.get("ruleId"))

    inventory_sha256 = _canonical_hash(inventory_material)
    target_sha256 = _canonical_hash(target_context)
    stale_reasons = []
    if expected_inventory_sha256 and expected_inventory_sha256 != inventory_sha256:
        stale_reasons.append("Current recursive source inventory hash differs from the expected plan.")
    if expected_target_sha256 and expected_target_sha256 != target_sha256:
        stale_reasons.append("Locked qualification target differs from the expected plan.")
    counts: dict[str, int] = {}
    for item in rules:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "version": 1,
        "status": "stale-plan" if stale_reasons else "planned",
        "solution": root.name,
        "target": target_context,
        "targetSha256": target_sha256,
        "inventory": {
            "complete": True,
            "recursiveRuleCount": len(rules),
            "sha256": inventory_sha256,
            "statuses": counts,
        },
        "groups": sorted(
            grouped.values(),
            key=lambda item: (item["table"].casefold(), item["schemaFingerprint"]),
        ),
        "rules": rules,
        "staleReasons": stale_reasons,
        "writesPerformed": False,
        "cloudCallsPerformed": False,
        "scope": "structured mock ingestion only; no connector/parser validation",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solution", required=True, type=Path)
    parser.add_argument("--target-context", required=True, type=Path)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--expected-inventory-sha256")
    parser.add_argument("--expected-target-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        target = _load_target(args.target_context)
        plan = build_plan(
            args.solution,
            target,
            registry_path=args.registry,
            expected_inventory_sha256=args.expected_inventory_sha256,
            expected_target_sha256=args.expected_target_sha256,
        )
        output = json.dumps(plan, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            if args.output.exists():
                raise FileExistsError(
                    f"plan output already exists; choose a new evidence path: {args.output}"
                )
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        return 1 if plan["status"] == "stale-plan" else 0
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
