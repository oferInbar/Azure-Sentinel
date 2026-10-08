from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from .artifacts import report_directory, portable_artifact, write_json_artifact
from .catalog import referenced_catalog_tables, referenced_custom_tables
from .converter import custom_detail_schema_errors, xdr_detection_files
from .content_paths import content_path, yaml_files
from .onboarding import (
    AUTH_RECORD_NAME,
    CONFIG_NAME,
    GRAPH_CLIENT_ID,
    GRAPH_SCOPE,
    TOKEN_CACHE_NAME,
    _load_auth_record,
    _read_json,
    _state_dir,
)
from .report import write_runtime_validation_report

ADVANCED_HUNTING_ENDPOINT = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
PROVIDER_PLATFORMS = {
    "graph": "Microsoft Defender XDR Advanced Hunting",
    "triage-mcp": "Microsoft Sentinel Triage MCP",
    "log-analytics-cli": "Microsoft Sentinel Log Analytics",
}
PROVIDER_QUERY_SURFACES = {
    "graph": "defender-advanced-hunting",
    "triage-mcp": "microsoft-sentinel-triage",
    "log-analytics-cli": "log-analytics-workspace",
}
SUPPORTED_EXTERNAL_PROVIDERS = frozenset(
    provider for provider in PROVIDER_PLATFORMS if provider != "graph"
)
PROVIDER_GAP_CODES = frozenset({
    "tool-unavailable",
    "authentication",
    "authorization",
    "timeout",
    "transient-provider-error",
    "batch-provider-failure",
})


def _detection_files(output: Path) -> list[Path]:
    return xdr_detection_files(output)


def _referenced_solution_functions(root: Path, query: str) -> set[str]:
    functions: set[str] = set()
    parser_root = root / "Parsers"
    if not parser_root.exists():
        return functions
    for path in yaml_files(parser_root):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
        except (OSError, yaml.YAMLError):
            continue
        name = str(document.get("FunctionName") or "").strip()
        if name and re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", query
        ):
            functions.add(name)
    return functions


def _write_runtime_artifacts(
    root: Path,
    provider: str,
    results: list[dict[str, Any]],
    *,
    table_availability: dict[str, Any] | None = None,
    provider_fallback: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output = report_directory(root, create=True)
    summary = {
        "solution": str(root),
        "platform": PROVIDER_PLATFORMS[provider],
        "querySurface": PROVIDER_QUERY_SURFACES[provider],
        "provider": provider,
        "total": len(results),
        "valid": sum(item["status"] == "passed" for item in results),
        "invalid": sum(item["status"] == "failed" for item in results),
        "blocked": sum(item["status"] == "blocked" for item in results),
        "notRun": sum(item["status"] == "not-run" for item in results),
        "tableAvailability": table_availability or {},
        "providerFallback": provider_fallback,
        "results": results,
    }
    json_path = output / f"runtime-validation.{provider}.json"
    html_path = output / f"runtime-validation.{provider}.html"
    summary["jsonReport"] = str(json_path)
    summary["htmlReport"] = str(html_path)
    write_json_artifact(root, json_path, summary)
    write_runtime_validation_report(portable_artifact(root, summary), html_path)
    return summary


def _query_sha256(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _source_query(root: Path, detection: dict[str, Any]) -> str:
    source = ((detection.get("contentProvenance") or {}).get("source") or {})
    source_reference = source.get("path")
    if not isinstance(source_reference, str) or not source_reference:
        raise ValueError("Custom Detection provenance must identify its source Analytic Rule")
    source_path = content_path(root, source_reference)
    with source_path.open(encoding="utf-8-sig") as handle:
        document = yaml.safe_load(handle) or {}
    if not isinstance(document, dict) or not isinstance(document.get("query"), str):
        raise ValueError(f"source Analytic Rule has no query: {source_reference}")
    return document["query"]


def current_runtime_query_hash(
    root: Path,
    detection_path: Path,
    *,
    provider: str,
) -> str:
    with detection_path.open(encoding="utf-8-sig") as handle:
        document = yaml.safe_load(handle) or {}
    if provider == "graph":
        query = (((document.get("properties") or {}).get("queryCondition") or {}).get("queryText"))
        if not isinstance(query, str):
            raise ValueError("Custom Detection has no Advanced Hunting query")
        return _query_sha256(query)
    return _query_sha256(_source_query(root, document))


def current_runtime_evidence(solution: str | Path) -> dict[str, Any]:
    """Require complete, exact-query evidence for both sides of the validation family."""
    root = Path(solution).expanduser().resolve()
    output = root / "XDR Detections"
    paths = {
        path.relative_to(output).as_posix(): path
        for path in _detection_files(output)
    }
    if not paths:
        return {"passed": False, "issues": ["no converted detections are available for runtime validation"]}

    issues: list[str] = []
    current_query_failures: list[str] = []
    graph_hashes = {
        name: current_runtime_query_hash(root, path, provider="graph")
        for name, path in paths.items()
    }
    source_reports = []
    for provider in ("triage-mcp", "log-analytics-cli"):
        report_path = report_directory(root) / f"runtime-validation.{provider}.json"
        if report_path.is_file():
            source_reports.append((provider, report_path))
    graph_path = report_directory(root) / "runtime-validation.graph.json"

    def inspect_family(
        provider: str,
        report_path: Path,
        expected_hashes: dict[str, str],
    ) -> tuple[bool, list[str]]:
        if not report_path.is_file():
            return False, [f"{provider} runtime report is missing"]
        try:
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return False, [f"{provider} runtime report is invalid"]
        if not isinstance(report, dict) or report.get("provider") != provider:
            return False, [f"{provider} runtime report provider does not match"]
        entries = report.get("results")
        if not isinstance(entries, list):
            return False, [f"{provider} runtime report has no results list"]
        by_name: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("detection") or "").replace("\\", "/")
            if name in by_name:
                return False, [f"{provider} runtime report has duplicate results for {name}"]
            by_name[name] = entry
        if set(by_name) != set(expected_hashes):
            return False, [
                f"{provider} runtime report is not a complete detection family "
                f"(missing={sorted(set(expected_hashes) - set(by_name))}, "
                f"unknown={sorted(set(by_name) - set(expected_hashes))})"
            ]
        failures = []
        for name, expected_hash in expected_hashes.items():
            entry = by_name[name]
            hash_matches = entry.get("querySha256") == expected_hash
            if entry.get("status") == "failed" and hash_matches:
                current_query_failures.append(
                    f"{provider} query validation failed for {name}: "
                    f"{entry.get('error') or 'provider reported a KQL/runtime failure'}"
                )
            if entry.get("status") != "passed":
                failures.append(f"{provider} validation for {name} is {entry.get('status')!r}")
            elif not hash_matches:
                failures.append(
                    f"{provider} validation for {name} is stale or unbound to the exact current query"
                )
        return not failures, failures

    source_passed = False
    source_provider_used = None
    source_issues: list[str] = []
    for provider, report_path in source_reports:
        passed, family_issues = inspect_family(
            provider,
            report_path,
            {
                name: current_runtime_query_hash(root, path, provider=provider)
                for name, path in paths.items()
            },
        )
        if passed:
            source_passed = True
            source_provider_used = provider
            break
        source_issues.extend(family_issues)
    if not source_passed:
        issues.extend(source_issues or ["no Sentinel runtime validation report is available"])

    graph_passed, graph_issues = inspect_family("graph", graph_path, graph_hashes)
    if not graph_passed:
        issues.extend(graph_issues)
    return {
        "passed": source_passed and graph_passed,
        "sentinelProvider": source_provider_used,
        "currentQueryFailures": current_query_failures,
        "issues": issues,
        "sentinelReport": (
            str(report_directory(root) / f"runtime-validation.{source_provider_used}.json")
            if source_provider_used else None
        ),
        "graphReport": str(graph_path) if graph_passed else None,
    }


def _load_provider_fallback(
    path: str | Path | None,
    *,
    query_family: str,
    fallback_provider: str,
) -> dict[str, Any] | None:
    if path is None:
        return None
    evidence = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        raise ValueError("provider-gap evidence must be a JSON object")
    if (
        evidence.get("mcpProvider") != "triage-mcp"
        or evidence.get("queryFamily") != query_family
        or evidence.get("fallbackProvider") != fallback_provider
        or evidence.get("reasonCode") not in PROVIDER_GAP_CODES
        or evidence.get("batchComplete") is not True
        or evidence.get("scopeVerified") is not True
        or evidence.get("permissionsVerified") is not True
        or evidence.get("kqlError") is not False
    ):
        raise ValueError(
            "provider-gap evidence must record an official Triage provider failure, "
            "the complete query-family fallback, exact scope and permissions, and no KQL error"
        )
    tool_name = evidence.get("advertisedTool")
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("provider-gap evidence requires the advertised Triage tool name or 'unavailable'")
    scope_reference = evidence.get("scopeReference")
    if not isinstance(scope_reference, str) or not scope_reference.strip() or len(scope_reference) > 500:
        raise ValueError("provider-gap evidence requires the exact scoped target reference")
    reason = evidence.get("reason")
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 500:
        raise ValueError("provider-gap evidence requires a concise reason of at most 500 characters")
    return {
        "mcpProvider": "triage-mcp",
        "advertisedTool": tool_name.strip(),
        "queryFamily": query_family,
        "fallbackProvider": fallback_provider,
        "scopeReference": scope_reference.strip(),
        "reasonCode": evidence["reasonCode"],
        "reason": reason.strip(),
        "batchComplete": True,
        "scopeVerified": True,
        "permissionsVerified": True,
        "kqlError": False,
    }


def _advanced_hunting_token(
    state_root: Path,
    *,
    tenant_id: str | None = None,
) -> str:
    from azure.identity import DeviceCodeCredential, TokenCachePersistenceOptions

    record = _load_auth_record(state_root / AUTH_RECORD_NAME)
    if record is None:
        raise RuntimeError(
            "Advanced Hunting authentication is missing; run "
            "`sentinel-xdr-migration setup` first"
        )
    config = _read_json(state_root / CONFIG_NAME)
    configured_tenant = config.get("tenantId") or getattr(record, "tenant_id", None)
    if tenant_id and configured_tenant and tenant_id.lower() != configured_tenant.lower():
        raise RuntimeError(
            "Advanced Hunting authentication tenant does not match the locked target"
        )
    credential = DeviceCodeCredential(
        client_id=GRAPH_CLIENT_ID,
        tenant_id=tenant_id or configured_tenant,
        authentication_record=record,
        cache_persistence_options=TokenCachePersistenceOptions(name=TOKEN_CACHE_NAME),
        disable_automatic_authentication=True,
    )
    return credential.get_token(GRAPH_SCOPE).token


def run_advanced_hunting_query(
    query: str,
    *,
    state_dir: str | Path | None = None,
    timeout: int = 90,
    retries: int = 2,
    _token: str | None = None,
) -> dict[str, Any]:
    token = _token or _advanced_hunting_token(_state_dir(state_dir))
    request = urllib.request.Request(
        ADVANCED_HUNTING_ENDPOINT,
        data=json.dumps({"Query": query}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    result: dict[str, Any] = {}
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
                status_code = response.status
            rows = body.get("results") or body.get("Results") or []
            return {
                "ok": True,
                "statusCode": status_code,
                "rowCount": len(rows),
                "schema": body.get("schema") or body.get("Schema") or [],
                "error": None,
                "errorDetails": None,
            }
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(body)
                error = parsed.get("error") or {}
                message = error.get("message") or body
            except json.JSONDecodeError:
                message = body
            result = {
                "ok": False,
                "statusCode": exc.code,
                "rowCount": 0,
                "schema": [],
                "error": message[:2000],
                "errorDetails": body[:8000],
            }
            if exc.code not in {429, 502, 503, 504} or attempt == retries:
                return result
        except (TimeoutError, urllib.error.URLError) as exc:
            result = {
                "ok": False,
                "statusCode": 0,
                "rowCount": 0,
                "schema": [],
                "error": str(exc),
                "errorDetails": str(exc),
            }
            if attempt == retries:
                return result
        time.sleep(2 * (attempt + 1))
    return result


def validate_advanced_hunting(
    solution: str | Path,
    *,
    state_dir: str | Path | None = None,
    tenant_id: str | None = None,
    provider_gap_evidence: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(solution).expanduser().resolve()
    provider_fallback = _load_provider_fallback(
        provider_gap_evidence,
        query_family="advanced-hunting",
        fallback_provider="graph",
    )
    output = root / "XDR Detections"
    results: list[dict[str, Any]] = []
    token = _advanced_hunting_token(_state_dir(state_dir), tenant_id=tenant_id)
    table_status: dict[str, dict[str, Any]] = {}
    for path in _detection_files(output):
        with path.open(encoding="utf-8-sig") as handle:
            document = yaml.safe_load(handle) or {}
        query = document["properties"]["queryCondition"]["queryText"]
        unavailable: list[str] = []
        dependencies = (
            referenced_catalog_tables(query)
            | referenced_custom_tables(query)
            | _referenced_solution_functions(root, query)
        )
        for dependency in sorted(dependencies):
            if dependency not in table_status:
                table_status[dependency] = run_advanced_hunting_query(
                    f"{dependency} | take 0", _token=token
                )
            if not table_status[dependency]["ok"]:
                unavailable.append(dependency)
        if unavailable:
            results.append(
                {
                    "detection": path.relative_to(output).as_posix(),
                    "status": "blocked",
                    "valid": False,
                    "querySha256": _query_sha256(query),
                    "statusCode": 0,
                    "rowCount": 0,
                    "schemaColumnCount": 0,
                    "error": (
                        "required Advanced Hunting table or function is unavailable in the "
                        f"current tenant: {', '.join(unavailable)}"
                    ),
                    "errorDetails": None,
                }
            )
            continue
        runtime = run_advanced_hunting_query(query, _token=token)
        binding_errors = custom_detail_schema_errors(document, runtime["schema"]) if runtime["ok"] else []
        results.append(
            {
                "detection": path.relative_to(output).as_posix(),
                "status": "passed" if runtime["ok"] and not binding_errors else "failed",
                "valid": runtime["ok"] and not binding_errors,
                "querySha256": _query_sha256(query),
                "statusCode": runtime["statusCode"],
                "rowCount": runtime["rowCount"],
                "schemaColumnCount": len(runtime["schema"]),
                "error": "; ".join(binding_errors) if binding_errors else runtime["error"],
                "errorDetails": runtime["errorDetails"],
            }
        )
    return _write_runtime_artifacts(
        root,
        "graph",
        results,
        table_availability={
            table: {
                "available": status["ok"],
                "statusCode": status["statusCode"],
                "error": status["error"],
            }
            for table, status in table_status.items()
        },
        provider_fallback=provider_fallback,
    )


def record_runtime_validation(
    solution: str | Path,
    *,
    provider: str,
    results_path: str | Path,
    provider_gap_evidence: str | Path | None = None,
) -> dict[str, Any]:
    if provider not in SUPPORTED_EXTERNAL_PROVIDERS:
        raise ValueError(
            f"unsupported external runtime provider {provider!r}; "
            f"expected one of {sorted(SUPPORTED_EXTERNAL_PROVIDERS)}"
        )
    provider_fallback = _load_provider_fallback(
        provider_gap_evidence,
        query_family="sentinel",
        fallback_provider="log-analytics-cli",
    )
    if provider_fallback and provider != "log-analytics-cli":
        raise ValueError("Sentinel MCP fallback results must be recorded under log-analytics-cli")
    root = Path(solution).expanduser().resolve()
    output = root / "XDR Detections"
    detection_paths = {path.relative_to(output).as_posix(): path for path in _detection_files(output)}
    expected = set(detection_paths)
    raw = json.loads(Path(results_path).expanduser().read_text(encoding="utf-8"))
    entries = raw.get("results") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("runtime results must be a JSON list or an object containing results")

    preflight_names = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each runtime result must be a JSON object")
        detection = str(entry.get("detection") or "").strip().replace("\\", "/")
        if not detection:
            raise ValueError("each runtime result requires a detection filename")
        preflight_names.append(detection)
    if len(preflight_names) != len(set(preflight_names)):
        raise ValueError("duplicate runtime result for a detection")
    preflight_set = set(preflight_names)
    if preflight_set != expected:
        details = []
        missing = sorted(expected - preflight_set)
        unknown = sorted(preflight_set - expected)
        if missing:
            details.append(f"missing detections: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown detections: {', '.join(unknown)}")
        raise ValueError("; ".join(details))

    expected_query_hashes = {
        name: current_runtime_query_hash(root, path, provider=provider)
        for name, path in detection_paths.items()
    }
    normalized: list[dict[str, Any]] = []
    names: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("each runtime result must be a JSON object")
        detection = str(entry.get("detection") or "").strip()
        if not detection:
            raise ValueError("each runtime result requires a detection filename")
        detection = detection.replace("\\", "/")
        if detection in names:
            raise ValueError(f"duplicate runtime result for {detection}")
        names.add(detection)
        status = str(entry.get("status") or "").strip().lower()
        if not status:
            status = "passed" if entry.get("valid") is True else "failed"
        if status not in {"passed", "failed", "blocked", "not-run"}:
            raise ValueError(f"invalid runtime status {status!r} for {detection}")
        error = entry.get("error")
        schema = entry.get("schema")
        query_hash = entry.get("querySha256")
        if status == "passed" and detection in expected_query_hashes:
            if not isinstance(query_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", query_hash):
                status = "blocked"
                error = (
                    "passed Sentinel validation must include the query hash (SHA-256) of the exact "
                    "source query that was executed"
                )
            elif query_hash != expected_query_hashes[detection]:
                status = "blocked"
                error = (
                    "Sentinel validation query hash is stale; rerun the complete Sentinel "
                    "query family against the current source queries"
                )
        if status == "passed" and detection in detection_paths:
            document = yaml.safe_load(detection_paths[detection].read_text(encoding="utf-8-sig")) or {}
            details = (
                ((document.get("properties") or {}).get("detectionAction") or {}).get("alertTemplate") or {}
            ).get("customDetails")
            if details:
                if not isinstance(schema, list):
                    status = "blocked"
                    error = "customDetails binding verification requires the returned target-query output schema, not just schemaColumnCount"
                else:
                    binding_errors = custom_detail_schema_errors(document, schema)
                    if binding_errors:
                        status = "failed"
                        error = "; ".join(binding_errors)
        normalized.append(
            {
                "detection": detection,
                "status": status,
                "valid": status == "passed",
                "querySha256": query_hash,
                "statusCode": int(entry.get("statusCode") or 0),
                "rowCount": int(entry.get("rowCount") or 0),
                "schemaColumnCount": len(schema) if isinstance(schema, list) else int(entry.get("schemaColumnCount") or 0),
                "error": error,
                "errorDetails": entry.get("errorDetails"),
            }
        )

    if provider_fallback and any(item["status"] == "failed" for item in normalized):
        raise ValueError(
            "provider fallback is not allowed when the fallback family contains a "
            "KQL/runtime failure; retain the failure and do not relabel it as a provider gap"
        )

    missing = sorted(expected - names)
    unknown = sorted(names - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing detections: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown detections: {', '.join(unknown)}")
        raise ValueError("; ".join(details))
    return _write_runtime_artifacts(
        root, provider, normalized, provider_fallback=provider_fallback,
    )
