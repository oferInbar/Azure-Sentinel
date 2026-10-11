from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
MAX_GRAPH_IN_FLIGHT_REQUESTS = 5
MAX_ADVANCED_HUNTING_RETRIES = 3
ADVANCED_HUNTING_RETRY_BUDGET_SECONDS = 5 * 60
_GRAPH_REQUEST_SEMAPHORE = threading.BoundedSemaphore(MAX_GRAPH_IN_FLIGHT_REQUESTS)
PROVIDER_PLATFORMS = {
    "graph": "Microsoft Defender XDR Advanced Hunting",
    "triage-mcp": "Microsoft Sentinel Triage MCP",
    "log-analytics-cli": "Microsoft Sentinel Log Analytics",
    "azure-monitor-sdk": "Microsoft Sentinel Log Analytics (Azure Monitor Query SDK)",
}
PROVIDER_QUERY_SURFACES = {
    "graph": "defender-advanced-hunting",
    "triage-mcp": "microsoft-sentinel-triage",
    "log-analytics-cli": "log-analytics-workspace",
    "azure-monitor-sdk": "log-analytics-workspace",
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
    provider_failure: dict[str, Any] | None = None,
    family_complete: bool | None = None,
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
    if family_complete is not None:
        summary["familyComplete"] = family_complete
    if provider_failure:
        summary["providerFailure"] = provider_failure
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
    for provider in ("triage-mcp", "azure-monitor-sdk", "log-analytics-cli"):
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
    available_source_reports = [
        (provider, report_path)
        for provider, report_path in source_reports
        if report_path.is_file()
    ]
    for index, (provider, report_path) in enumerate(available_source_reports):
        if index:
            previous_provider, previous_path = available_source_reports[0]
            try:
                previous_report = json.loads(previous_path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                break
            if (
                previous_provider != "triage-mcp"
                or not isinstance(previous_report, dict)
                or not isinstance(previous_report.get("providerFailure"), dict)
            ):
                break
            try:
                fallback_report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                break
            proof = fallback_report.get("providerFallback") if isinstance(fallback_report, dict) else None
            if (
                not isinstance(proof, dict)
                or proof.get("mcpProvider") != "triage-mcp"
                or proof.get("fallbackProvider") != provider
                or proof.get("batchComplete") is not True
                or proof.get("permissionsVerified") is not True
                or proof.get("kqlError") is not False
            ):
                continue
        current_failures_before = len(current_query_failures)
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
        if len(current_query_failures) > current_failures_before:
            break
        try:
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            break
        if (
            provider != "triage-mcp"
            or not isinstance(report, dict)
            or not isinstance(report.get("providerFailure"), dict)
        ):
            break
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


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        retry_at = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)
    now = datetime.fromtimestamp(time.time(), timezone.utc)
    return max(0.0, (retry_at - now).total_seconds())


def _http_retry_after(exc: urllib.error.HTTPError) -> float | None:
    headers = getattr(exc, "headers", None)
    value = headers.get("Retry-After") if headers is not None else None
    return _retry_after_seconds(value)


def run_advanced_hunting_query(
    query: str,
    *,
    state_dir: str | Path | None = None,
    timeout: int = 90,
    retries: int = 2,
    _token: str | None = None,
) -> dict[str, Any]:
    """Run one Graph Advanced Hunting read within this process's provider bounds.

    The in-process semaphore limits actual Graph requests to five at a time;
    imported Log Analytics/MCP results are external and are not governed here.
    Transient attempts share a five-minute wall-clock budget, including request
    durations and retry waits. The public retry default remains two.
    """
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
    retry_limit = max(0, min(retries, MAX_ADVANCED_HUNTING_RETRIES))
    deadline = time.monotonic() + ADVANCED_HUNTING_RETRY_BUDGET_SECONDS
    for attempt in range(retry_limit + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        acquired = _GRAPH_REQUEST_SEMAPHORE.acquire(timeout=remaining)
        if not acquired:
            result = {
                "ok": False,
                "statusCode": 0,
                "rowCount": 0,
                "schema": [],
                "error": "Timed out waiting for an available Graph request slot",
                "errorDetails": "The Advanced Hunting retry budget expired while waiting for a request slot",
                "failureKind": "provider",
            }
            return result
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            with urllib.request.urlopen(request, timeout=min(timeout, remaining)) as response:
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
                "failureKind": "query" if exc.code == 400 else "provider",
            }
            if exc.code not in {429, 502, 503, 504} or attempt == retry_limit:
                return result
            retry_after = _http_retry_after(exc)
        except (TimeoutError, urllib.error.URLError) as exc:
            result = {
                "ok": False,
                "statusCode": 0,
                "rowCount": 0,
                "schema": [],
                "error": str(exc),
                "errorDetails": str(exc),
                "failureKind": "provider",
            }
            if attempt == retry_limit:
                return result
            retry_after = None
        finally:
            _GRAPH_REQUEST_SEMAPHORE.release()

        remaining = deadline - time.monotonic()
        delay = retry_after if retry_after is not None else 2 * (attempt + 1)
        if delay >= remaining:
            return result
        if delay:
            time.sleep(delay)
    if result:
        return result
    return {
        "ok": False,
        "statusCode": 0,
        "rowCount": 0,
        "schema": [],
        "error": "Advanced Hunting retry budget expired before a request could complete",
        "errorDetails": "The five-minute request and retry budget was exhausted",
        "failureKind": "provider",
    }


def _not_run_result(
    path: Path, output: Path, query: str, *, status_code: int = 0
) -> dict[str, Any]:
    return {
        "detection": path.relative_to(output).as_posix(),
        "status": "not-run",
        "valid": False,
        "querySha256": _query_sha256(query),
        "statusCode": status_code,
        "rowCount": 0,
        "schemaColumnCount": 0,
        "error": None,
        "errorDetails": None,
    }


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
    detections: list[tuple[Path, dict[str, Any], str]] = []
    for path in _detection_files(output):
        with path.open(encoding="utf-8-sig") as handle:
            document = yaml.safe_load(handle) or {}
        query = document["properties"]["queryCondition"]["queryText"]
        detections.append((path, document, query))

    provider_failure: dict[str, Any] | None = None
    for path, document, query in detections:
        if provider_failure:
            results.append(_not_run_result(path, output, query))
            continue
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
                if table_status[dependency].get("failureKind") == "provider":
                    break
        if unavailable:
            provider_error = next(
                (
                    table_status[dependency]
                    for dependency in unavailable
                    if table_status[dependency].get("failureKind") == "provider"
                ),
                None,
            )
            if provider_error:
                provider_failure = {
                    "provider": "graph",
                    "statusCode": provider_error["statusCode"],
                    "error": provider_error["error"],
                    "errorDetails": provider_error["errorDetails"],
                }
                results.append(
                    _not_run_result(
                        path,
                        output,
                        query,
                        status_code=provider_error["statusCode"],
                    )
                )
                continue
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
        if runtime.get("failureKind") == "provider":
            provider_failure = {
                "provider": "graph",
                "statusCode": runtime["statusCode"],
                "error": runtime["error"],
                "errorDetails": runtime["errorDetails"],
            }
            results.append(
                _not_run_result(
                    path, output, query, status_code=runtime["statusCode"]
                )
            )
            continue
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
        provider_failure=provider_failure,
    )


def validate_sentinel_sdk(
    solution: str | Path,
    *,
    target: dict[str, str],
    request_timeout_seconds: int = 90,
    family_timeout_seconds: int = 30 * 60,
    provider_gap_evidence: str | Path | None = None,
    _credential_factory=None,
    _client_factory=None,
    _scope_verifier=None,
    _monotonic=None,
    _sleep=None,
) -> dict[str, Any]:
    """Run the complete current Sentinel source-query family with Azure Monitor SDK."""
    from .content_paths import content_path
    from .converter import analytic_rule_files, solution_paths, xdr_detection_files
    from .logs_query import (
        DEFAULT_FAMILY_TIMEOUT_SECONDS,
        DEFAULT_REQUEST_TIMEOUT_SECONDS,
        azure_cli_credential,
        execute_workspace_query,
        logs_query_client,
        query_family,
        verify_azure_cli_target,
    )

    root, analytic, output = solution_paths(solution)
    provider = "azure-monitor-sdk"
    provider_fallback = _load_provider_fallback(
        provider_gap_evidence,
        query_family="sentinel",
        fallback_provider=provider,
    )
    sources = analytic_rule_files(root)
    if not sources:
        raise ValueError("complete Sentinel source-query inventory is empty; no SDK validation report was written")

    source_by_path: dict[str, tuple[Path, str, str]] = {}
    for source_path in sources:
        relative = source_path.relative_to(analytic).as_posix()
        with source_path.open(encoding="utf-8-sig") as handle:
            source = yaml.safe_load(handle)
        if not isinstance(source, dict) or not isinstance(source.get("query"), str) or not source["query"].strip():
            raise ValueError(f"source Analytic Rule has no non-empty query: {source_path}")
        query = source["query"]
        source_by_path[relative] = (source_path, query, _query_sha256(query))

    detections: dict[str, str] = {}
    for detection_path in xdr_detection_files(output):
        with detection_path.open(encoding="utf-8-sig") as handle:
            detection = yaml.safe_load(handle)
        source_ref = ((detection or {}).get("contentProvenance") or {}).get("source") or {}
        source_path_ref = source_ref.get("path")
        if not isinstance(source_path_ref, str):
            raise ValueError(f"Custom Detection provenance is missing its source path: {detection_path}")
        source_path = content_path(root, source_path_ref)
        if not source_path.is_file():
            raise ValueError(f"Custom Detection source Analytic Rule is missing: {source_path_ref}")
        relative = source_path.relative_to(analytic).as_posix()
        if relative not in source_by_path:
            raise ValueError(f"Custom Detection provenance is outside the complete source inventory: {source_path_ref}")
        if relative in detections.values():
            raise ValueError(f"multiple Custom Detections refer to the same source Analytic Rule: {source_path_ref}")
        current_hash = source_by_path[relative][2]
        if source_ref.get("querySha256") != current_hash:
            raise ValueError(f"Custom Detection provenance has a stale source-query hash: {source_path_ref}")
        detections[detection_path.relative_to(output).as_posix()] = relative

    if set(detections.values()) != set(source_by_path):
        raise ValueError(
            "SDK validation requires the complete source inventory to map one-to-one to "
            "generated detections "
            f"(missing={sorted(set(source_by_path) - set(detections.values()))}, "
            f"extra={sorted(set(detections.values()) - set(source_by_path))})"
        )
    queries = [
        {
            "detection": detection,
            "query": source_by_path[source_relative][1],
            "querySha256": source_by_path[source_relative][2],
        }
        for detection, source_relative in sorted(detections.items())
    ]

    results: list[dict[str, Any]]
    provider_failure = None
    scope_verifier = _scope_verifier or verify_azure_cli_target
    try:
        scope_verifier(target)
        credential_factory = _credential_factory or azure_cli_credential
        client_factory = _client_factory or logs_query_client
        credential = credential_factory(target)
        client = client_factory(credential, retry_total=0)
        try:
            results = query_family(
                client,
                target["workspaceCustomerId"],
                queries,
                request_timeout_seconds=request_timeout_seconds,
                family_timeout_seconds=(
                    family_timeout_seconds
                    if family_timeout_seconds is not None
                    else DEFAULT_FAMILY_TIMEOUT_SECONDS
                ),
                monotonic=_monotonic or time.monotonic,
                sleep=_sleep or time.sleep,
            )
            provider_failure_result = next(
                (
                    item for item in results
                    if item.get("failureKind") not in {
                        None, "query", "partial-response",
                    }
                ),
                None,
            )
            if provider_failure_result:
                provider_failure = {
                    "failureKind": provider_failure_result.get("failureKind"),
                    "statusCode": provider_failure_result.get("statusCode", 0),
                    "error": provider_failure_result.get("error"),
                    "errorDetails": provider_failure_result.get("errorDetails"),
                }
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()
    except Exception as exc:
        if isinstance(exc, (ValueError, TypeError)):
            raise
        failure_kind = getattr(exc, "failure_kind", "provider")
        provider_failure = {
            "failureKind": failure_kind,
            "statusCode": int(getattr(exc, "status_code", 0) or 0),
            "error": str(exc)[:2000],
            "errorDetails": str(getattr(exc, "error_details", exc))[:8000],
        }
        results = [
            {
                "detection": item["detection"],
                "status": "not-run",
                "valid": False,
                "querySha256": item["querySha256"],
                "statusCode": provider_failure["statusCode"],
                "rowCount": 0,
                "schema": [],
                "error": "query was not dispatched because provider initialization or target authentication failed",
                "errorDetails": provider_failure["error"],
            }
            for item in queries
        ]
    family_complete = len(results) == len(queries) and all(
        item.get("status") != "not-run" for item in results
    )
    report = record_runtime_validation(
        root,
        provider=provider,
        results_data=results,
        provider_gap_evidence=provider_gap_evidence,
        provider_failure=provider_failure,
        family_complete=family_complete,
    )
    return report


def record_runtime_validation(
    solution: str | Path,
    *,
    provider: str,
    results_path: str | Path | None = None,
    results_data: list[dict[str, Any]] | None = None,
    provider_gap_evidence: str | Path | None = None,
    provider_failure: dict[str, Any] | None = None,
    family_complete: bool | None = None,
) -> dict[str, Any]:
    if provider not in SUPPORTED_EXTERNAL_PROVIDERS:
        raise ValueError(
            f"unsupported external runtime provider {provider!r}; "
            f"expected one of {sorted(SUPPORTED_EXTERNAL_PROVIDERS)}"
        )
    provider_fallback = _load_provider_fallback(
        provider_gap_evidence,
        query_family="sentinel",
        fallback_provider=provider,
    )
    if provider_fallback and provider != provider_fallback["fallbackProvider"]:
        raise ValueError("Sentinel MCP fallback results must be recorded under the approved fallback provider")
    root = Path(solution).expanduser().resolve()
    output = root / "XDR Detections"
    detection_paths = {path.relative_to(output).as_posix(): path for path in _detection_files(output)}
    expected = set(detection_paths)
    if (results_path is None) == (results_data is None):
        raise ValueError("provide exactly one of results_path or results_data")
    raw = (
        json.loads(Path(results_path).expanduser().read_text(encoding="utf-8"))
        if results_path is not None else results_data
    )
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
        if status == "passed" and provider == "graph" and detection in detection_paths:
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
        normalized_entry = {
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
        for field in ("tables", "partialError", "failureKind", "attempts", "durationMs"):
            if field in entry:
                normalized_entry[field] = entry[field]
        if entry.get("partial") is True:
            normalized_entry["partial"] = True
        normalized.append(normalized_entry)

    missing = sorted(expected - names)
    unknown = sorted(names - expected)
    if missing or unknown:
        details = []
        if missing:
            details.append(f"missing detections: {', '.join(missing)}")
        if unknown:
            details.append(f"unknown detections: {', '.join(unknown)}")
        raise ValueError("; ".join(details))

    fallback_rejection = None
    if provider_fallback:
        failed_results = [
            item for item in normalized if item["status"] != "passed"
        ]
        if failed_results or family_complete is False:
            reasons = [
                (
                    f"{item['detection']} is {item['status']}: "
                    f"{item.get('error') or item.get('errorDetails') or 'no query diagnostics returned'}"
                )
                for item in failed_results
            ]
            if family_complete is False:
                reasons.append("the query family is incomplete")
            fallback_rejection = (
                "provider fallback is not allowed unless every fallback query completed "
                "successfully; " + "; ".join(reasons)
            )

    report = _write_runtime_artifacts(
        root,
        provider,
        normalized,
        provider_fallback=provider_fallback,
        provider_failure=provider_failure,
        family_complete=family_complete,
    )
    if fallback_rejection:
        raise ValueError(
            f"{fallback_rejection}; attempt diagnostics were persisted to {report['jsonReport']}"
        )
    return report
