from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
import yaml

from .artifacts import (
    artifact_path, existing_artifact_path, resolve_artifact_reference,
    create_run, requested_run_id, solution_for_artifact, using_run, RUN_MARKER,
    conversion_scope, require_solution_conversion_scope, portable_artifact,
)
from .budget import (
    BudgetError,
    BudgetReceiptError,
    budget_summary,
    create_or_link_campaign,
    ensure_work_available,
    measured_operation,
    package_history,
    validate_campaign_binding,
)
from .authoring_contract import (
    AUTHORING_SCHEMA_VERSION,
    AuthoringContractError,
    calculate_inventory_sha256,
    seal_authoring_contract,
    validate_authoring_contract,
)
from .content_paths import content_path
from .converter import (
    BEST_EFFORT_ENTITY_REVIEW_PREFIX,
    SOURCE_ID_PATTERN,
    analytic_rule_files,
    inspect_solution,
    convert_solution,
    validate_document,
    validate_solution,
    solution_paths,
    xdr_detection_files,
)
from .target_context import build_target, write_target
from .packaging import (
    package_input_identity,
    package_solution_v3_1,
    solution_data_version,
    version_bump_was_consumed,
)
from .packaging_selection import (
    _partial_coverage_allowed,
    verify_applied_package_selection,
)
from .source_runtime_waiver import SOURCE_PROVIDERS, missing_schema_whitelist_match

STATE_FILE_NAME = "workflow-state.json"
SCHEMA_VERSION = "1.2.0"
WORKFLOW_PROFILES = ("authoring", "qualification")
STAGES = (
    "discovery",
    "conversion",
    "validation",
    "packaging",
    "deployment",
    "mockIngestion",
    "alertParity",
    "report",
)
QUALIFICATION_DEPENDENCIES = {
    "discovery": (),
    "conversion": ("discovery",),
    "validation": ("conversion",),
    "packaging": ("validation",),
    "deployment": ("packaging",),
    "mockIngestion": ("deployment",),
    "alertParity": ("mockIngestion",),
    "report": ("alertParity",),
}
AUTHORING_DEPENDENCIES = {
    "discovery": (),
    "conversion": ("discovery",),
    "validation": ("conversion",),
    "packaging": ("validation",),
    "report": ("packaging",),
}
AUTHORING_OPTIONAL_STAGES = {"deployment", "mockIngestion", "alertParity"}
TERMINAL_STATUSES = {"passed", "failed", "blocked"}
AUTHORING_CONTRACT_DIRECTORY = "authoring-contracts"
AUTHORING_LOCK_NAME = ".workflow-state.lock"
AUTHORING_CONTRACT_VERSION = "1.0.0"
_HELD_RUN_LOCKS: ContextVar[frozenset[str]] = ContextVar(
    "held_yolo_workflow_locks", default=frozenset()
)

try:
    import fcntl
except ImportError:
    fcntl = None
    import msvcrt


@contextmanager
def _run_writer_lock(run_directory: Path):
    """Serialize workflow-state and authoring-record writers; OS releases locks on exit."""
    run_directory.mkdir(parents=True, exist_ok=True)
    key = str(run_directory.resolve())
    held = _HELD_RUN_LOCKS.get()
    if key in held:
        yield
        return
    lock_path = run_directory / AUTHORING_LOCK_NAME
    with lock_path.open("a+b") as handle:
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        token = _HELD_RUN_LOCKS.set(held | {key})
        try:
            yield
        finally:
            _HELD_RUN_LOCKS.reset(token)
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", suffix=".tmp",
            dir=path.parent, delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _atomic_json(path: Path, value: Any) -> bytes:
    content = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    _atomic_write(path, content)
    return content


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _paths(solution: str | Path) -> tuple[Path, Path]:
    root = Path(solution).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"solution folder does not exist: {root}")
    return root, artifact_path(root, STATE_FILE_NAME)


def _schema() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "schema" / "workflow-state.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _validate(state: dict[str, Any]) -> None:
    errors = sorted(
        Draft202012Validator(_schema()).iter_errors(state),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        details = "; ".join(error.message for error in errors)
        raise ValueError(f"invalid workflow state: {details}")


def _migrate_workflow_state(state: dict[str, Any]) -> dict[str, Any]:
    """Add additive packaging lifecycle fields when reading pre-1.2 workflow state."""
    packaging = state.get("packaging")
    if isinstance(packaging, dict):
        packaging.setdefault("releaseActions", [])
        packaging.setdefault("pendingReleaseAction", None)
    return state


def _write_unlocked(path: Path, state: dict[str, Any]) -> None:
    root = solution_for_artifact(path)
    destination = artifact_path(root, STATE_FILE_NAME, create_parent=True)
    if path != destination:
        raise ValueError("workflow state path does not belong to the selected run")
    state["runId"] = destination.parent.name
    state["updatedAt"] = _utc_now()
    _validate(state)
    _atomic_json(path, portable_artifact(root, state))


def _write(path: Path, state: dict[str, Any]) -> None:
    with _run_writer_lock(path.parent):
        _write_unlocked(path, state)


@contextmanager
def _state_writer_lock(solution: str | Path):
    root, path = _paths(solution)
    with _run_writer_lock(path.parent):
        yield path


def _load(solution: str | Path) -> tuple[Path, dict[str, Any]]:
    root, _ = _paths(solution)
    path = existing_artifact_path(root, STATE_FILE_NAME)
    if not path.is_file():
        raise ValueError(
            f"workflow state does not exist: {path}; run workflow-init first"
        )
    state = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(state, dict):
        raise ValueError(f"workflow state must be a JSON object: {path}")
    if state.get("schemaVersion") == "1.1.0":
        state["schemaVersion"] = SCHEMA_VERSION
        _migrate_workflow_state(state)
    elif state.get("schemaVersion") == SCHEMA_VERSION:
        _migrate_workflow_state(state)
    context = state.get("context")
    if isinstance(context, dict):
        context.setdefault("profileSelectionConfirmed", False)
    _validate(state)
    if (path.parent / RUN_MARKER).is_file() and state.get("runId") != path.parent.name:
        raise ValueError("workflow state runId does not match its run directory")
    return artifact_path(root, STATE_FILE_NAME), state


def _stage_result(name: str, *, required: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "status": "pending" if required else "notRequired",
        "attempts": 0,
        "startedAt": None,
        "completedAt": None,
        "message": None if required else "not required for the authoring workflow",
        "artifacts": {},
        "evidence": [],
    }


def _source_inventory(solution: str | Path) -> list[dict[str, Any]]:
    root, analytic, _ = solution_paths(solution)
    files = analytic_rule_files(root)
    if not files:
        raise ValueError("YOLO requires a non-empty complete Analytic Rules inventory")
    inventory: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for path in files:
        source_bytes = path.read_bytes()
        try:
            document = yaml.safe_load(source_bytes.decode("utf-8-sig")) or {}
        except (UnicodeError, yaml.YAMLError) as exc:
            raise ValueError(f"cannot freeze source rule {path}: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError(f"source rule must be a YAML object: {path}")
        rule_id = document.get("id")
        query = document.get("query")
        if not isinstance(rule_id, str) or not re.fullmatch(SOURCE_ID_PATTERN, rule_id):
            raise ValueError(f"source rule has no valid full GUID identity: {path}")
        if rule_id.casefold() in seen_ids:
            raise ValueError(f"duplicate source rule identity in complete inventory: {rule_id}")
        if not isinstance(query, str) or not query.strip():
            raise ValueError(f"source rule has no non-empty query: {path}")
        seen_ids.add(rule_id.casefold())
        inventory.append({
            "ruleId": rule_id,
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(source_bytes).hexdigest(),
            "querySha256": hashlib.sha256(query.encode("utf-8")).hexdigest(),
            "evidenceReferences": [{
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(source_bytes).hexdigest(),
                "kind": "source",
            }],
        })
    inventory.sort(key=lambda item: item["path"])
    return inventory


def _budget_source_inventory(
    solution: str | Path,
    *,
    yolo: bool,
) -> tuple[str, list[str]]:
    root = Path(solution).expanduser().resolve()
    if yolo:
        inventory = _source_inventory(root)
        return (
            calculate_inventory_sha256(inventory),
            [rule["ruleId"] for rule in inventory],
        )
    has_rule_folder = any(
        (root / name).exists() or (root / name).is_symlink()
        for name in ("Analytic Rules", "Analytics Rules")
    )
    files = analytic_rule_files(root) if has_rule_folder else []
    rows = []
    rule_ids: set[str] = set()
    for path in files:
        content = path.read_bytes()
        rows.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
        try:
            document = yaml.safe_load(content.decode("utf-8-sig")) or {}
        except (UnicodeError, yaml.YAMLError):
            document = {}
        if (
            isinstance(document, dict)
            and isinstance(document.get("id"), str)
            and re.fullmatch(SOURCE_ID_PATTERN, document["id"])
        ):
            rule_ids.add(document["id"])
    digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return digest, sorted(rule_ids)


def _preflight_campaign_binding(
    solution: Path,
    campaign_id: str | None,
    *,
    yolo: bool,
    inventory: list[dict[str, Any]] | None = None,
) -> tuple[str, list[str]] | None:
    if campaign_id is None:
        return None
    if yolo:
        frozen = inventory if inventory is not None else _source_inventory(solution)
        inventory_hash = calculate_inventory_sha256(frozen)
        rule_ids = [rule["ruleId"] for rule in frozen]
    else:
        inventory_hash, rule_ids = _budget_source_inventory(solution, yolo=False)
    validate_campaign_binding(
        solution,
        campaign_id,
        inventory_sha256=inventory_hash,
        rule_ids=rule_ids,
    )
    return inventory_hash, rule_ids


def _initial_rule_result(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "ruleId": rule["ruleId"],
        "sourceSha256": rule["sha256"],
        "status": "unprocessed",
        "conversionStatus": "unprocessed",
        "validationStatus": "notRun",
        "deploymentDisposition": "normal",
        "target": None,
        "reviewRequired": False,
        "mappingAssumptions": [],
        "findings": [],
        "qualificationStatus": "untested",
        "qualificationEvidenceReferences": [],
        "evidenceReferences": [],
    }


def _contract_core(
    root: Path,
    run_id: str,
    inventory: list[dict[str, Any]],
    *,
    revision: int,
    previous_sha256: str | None,
    results: list[dict[str, Any]] | None = None,
    environment_errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    inventory_sha256 = calculate_inventory_sha256(inventory)
    return {
        "schemaVersion": AUTHORING_SCHEMA_VERSION,
        "runId": run_id,
        "snapshot": {
            "revision": revision,
            "previousSha256": previous_sha256,
        },
        "source": {
            "identity": root.name,
            "sha256": inventory_sha256,
        },
        "inventory": {
            "complete": True,
            "sha256": inventory_sha256,
            "rules": inventory,
        },
        "results": results or [_initial_rule_result(rule) for rule in inventory],
        "environmentErrors": environment_errors or [],
        "entityValueParityPolicy": {
            "assertion": "value-preserved-in-actual-corresponding-alert",
            "comparison": "value-only",
            "entityTypeIdentifierAndCustomFieldMayDiffer": True,
            "requiredForQualification": True,
        },
    }


def _persist_contract_snapshot(
    run_directory: Path,
    state: dict[str, Any],
    core_record: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    try:
        record = seal_authoring_contract(core_record)
    except AuthoringContractError as exc:
        raise ValueError(f"authoring contract is invalid: {exc}") from exc
    content = (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    digest = hashlib.sha256(content).hexdigest()
    revision = record["snapshot"]["revision"]
    relative = f"{AUTHORING_CONTRACT_DIRECTORY}/{revision:06d}-{digest}.json"
    destination = content_path(run_directory, relative)
    if destination.exists():
        if destination.read_bytes() != content:
            raise ValueError("authoring contract snapshot hash collision or conflicting artifact")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(destination, content)
    previous_authoring = state.get("authoring") or {}
    status = previous_authoring.get("status", "active")
    state["authoring"] = {
        "schemaVersion": AUTHORING_CONTRACT_VERSION,
        "mode": "yolo",
        "status": status,
        "inventorySha256": record["inventory"]["sha256"],
        "currentContract": {
            "path": relative,
            "sha256": digest,
            "revision": revision,
        },
        "stopReason": previous_authoring.get("stopReason"),
    }
    return record, digest


def _verify_source_inventory(
    solution: Path,
    contract_document: dict[str, Any],
) -> list[dict[str, Any]]:
    current = _source_inventory(solution)
    current_hash = calculate_inventory_sha256(current)
    if current_hash != contract_document["inventory"]["sha256"]:
        raise ValueError(
            "frozen YOLO source inventory is stale or changed; preserve edits and start a new run"
        )
    return current


def _load_contract_snapshot(
    run_directory: Path,
    reference: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    relative = reference["path"]
    snapshot_path = content_path(run_directory, relative)
    if snapshot_path.is_symlink() or not snapshot_path.is_file():
        raise ValueError("referenced authoring-contract snapshot is missing or unsafe")
    content = snapshot_path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != reference["sha256"] or snapshot_path.name != (
        f"{reference['revision']:06d}-{digest}.json"
    ):
        raise ValueError("authoring-contract snapshot hash or revision is stale")
    try:
        document = json.loads(content)
        typed = validate_authoring_contract(document)
    except (UnicodeError, json.JSONDecodeError, AuthoringContractError) as exc:
        raise ValueError(f"referenced authoring-contract snapshot is invalid: {exc}") from exc
    if (
        typed.run_id != run_directory.name
        or typed.revision != reference["revision"]
        or typed.inventory_sha256 != reference.get("inventorySha256", typed.inventory_sha256)
    ):
        raise ValueError("authoring-contract snapshot identity does not match workflow state")
    return document, content


def _recover_yolo_state(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Roll forward one atomically stored contract snapshot after an interrupted state write."""
    authoring = state.get("authoring")
    if not isinstance(authoring, dict) or authoring.get("mode") != "yolo":
        return state
    run_directory = state_path.parent
    current = authoring.get("currentContract")
    if not isinstance(current, dict):
        raise ValueError("YOLO workflow state has no current authoring-contract reference")
    current_document, _ = _load_contract_snapshot(run_directory, current)
    inventory = _verify_source_inventory(solution, current_document)
    if calculate_inventory_sha256(inventory) != authoring.get("inventorySha256"):
        raise ValueError("workflow inventory hash does not match its frozen contract")

    history = content_path(run_directory, AUTHORING_CONTRACT_DIRECTORY)
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    if history.exists():
        if history.is_symlink() or not history.is_dir():
            raise ValueError("authoring-contract history path is unsafe")
        for snapshot_path in sorted(history.glob("*.json")):
            if snapshot_path.is_symlink():
                raise ValueError("authoring-contract history contains an unsafe symlink")
            try:
                candidate_bytes = snapshot_path.read_bytes()
                candidate_hash = hashlib.sha256(candidate_bytes).hexdigest()
                candidate = json.loads(candidate_bytes)
                typed = validate_authoring_contract(candidate)
            except (OSError, UnicodeError, json.JSONDecodeError, AuthoringContractError) as exc:
                raise ValueError(f"invalid authoring-contract history snapshot: {snapshot_path.name}") from exc
            if snapshot_path.name != f"{typed.revision:06d}-{candidate_hash}.json":
                raise ValueError(f"authoring-contract history filename is stale: {snapshot_path.name}")
            if typed.run_id != run_directory.name or typed.inventory_sha256 != authoring["inventorySha256"]:
                raise ValueError("authoring-contract history contains a conflicting run or inventory")
            if (
                typed.revision == current["revision"] + 1
                and typed.previous_sha256 == current["sha256"]
            ):
                candidates.append((candidate, {
                    "path": snapshot_path.relative_to(run_directory).as_posix(),
                    "sha256": candidate_hash,
                    "revision": typed.revision,
                }))
    if len(candidates) > 1:
        raise ValueError("multiple authoring-contract recovery successors conflict")
    if not candidates:
        return state

    recovered, reference = candidates[0]
    authoring["currentContract"] = reference
    coverage = recovered["coverage"]
    if coverage["stopThresholdReached"] and authoring["status"] == "active":
        authoring["status"] = "stopped"
        authoring["stopReason"] = (
            f"Durable rule-error threshold reached: {coverage['E']}/{coverage['N']} "
            "(100*E > 50*N)."
        )
        state["workflowStatus"] = "blocked"
    _write_unlocked(state_path, state)
    return state


def _reference_for_file(root: Path, path: Path, kind: str) -> dict[str, str]:
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "kind": kind,
    }


def _runtime_observations(
    root: Path,
    run_directory: Path,
    inventory: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], bool]:
    """Consume existing provider reports only; never invent provider or query outcomes."""
    _, _, output = solution_paths(root)
    output_prefix = output.relative_to(root).as_posix() + "/"
    result_by_id = {item["ruleId"]: item for item in results}
    detection_to_rule: dict[str, str] = {}
    expected_hashes: dict[str, dict[str, str]] = {}
    for rule in inventory:
        result = result_by_id[rule["ruleId"]]
        target = result.get("target")
        if not target:
            continue
        target_path = target["path"]
        if not target_path.startswith(output_prefix):
            continue
        detection = target_path[len(output_prefix):]
        if detection in detection_to_rule:
            raise ValueError(f"duplicate generated target path in YOLO contract: {detection}")
        detection_to_rule[detection] = rule["ruleId"]
        expected_hashes[detection] = {
            "triage-mcp": rule["querySha256"],
            "azure-monitor-sdk": rule["querySha256"],
            "log-analytics-cli": rule["querySha256"],
            "graph": target.get("querySha256") or "",
        }

    runtime_findings: dict[str, list[dict[str, Any]]] = {
        rule["ruleId"]: [] for rule in inventory
    }
    environment_errors: list[dict[str, Any]] = []
    environment_keys: set[tuple[str, str]] = set()
    all_reports_passed = bool(expected_hashes)
    source_reports = [
        ("triage-mcp", run_directory / "runtime-validation.triage-mcp.json"),
        ("azure-monitor-sdk", run_directory / "runtime-validation.azure-monitor-sdk.json"),
        ("log-analytics-cli", run_directory / "runtime-validation.log-analytics-cli.json"),
    ]
    available_source_reports = [
        (provider, path) for provider, path in source_reports if path.is_file()
    ]
    selected_reports: list[tuple[str, Path]] = []
    if available_source_reports:
        selected = available_source_reports[0]
        if selected[0] == "triage-mcp":
            try:
                candidate = json.loads(selected[1].read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"existing {selected[0]} runtime report is invalid: {exc}") from exc
            if isinstance(candidate, dict) and isinstance(candidate.get("providerFailure"), dict):
                for fallback in available_source_reports[1:]:
                    fallback_document = json.loads(
                        fallback[1].read_text(encoding="utf-8-sig")
                    )
                    proof = (
                        fallback_document.get("providerFallback")
                        if isinstance(fallback_document, dict) else None
                    ) or {}
                    if (
                        proof.get("mcpProvider") == "triage-mcp"
                        and proof.get("fallbackProvider") == fallback[0]
                        and proof.get("batchComplete") is True
                        and proof.get("scopeVerified") is True
                        and proof.get("permissionsVerified") is True
                        and proof.get("kqlError") is False
                    ):
                        selected = fallback
                        break
        selected_reports.append(selected)
    if not selected_reports:
        all_reports_passed = False
    selected_reports.append(
        ("graph", run_directory / "runtime-validation.graph.json")
    )
    for provider, report_path in selected_reports:
        if not report_path.is_file():
            all_reports_passed = False
            continue
        try:
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"existing {provider} runtime report is invalid: {exc}") from exc
        if not isinstance(report, dict) or report.get("provider") != provider:
            raise ValueError(f"existing {provider} runtime report has a mismatched provider")
        reference = _reference_for_file(root, report_path, "runtimeVerification")
        shared_failure = False
        for field in ("providerFailure",):
            failure = report.get(field)
            if isinstance(failure, dict):
                shared_failure = True
                code = str(failure.get("code") or failure.get("failureKind") or "providerFailure")
                message = str(failure.get("error") or failure.get("message") or "Provider failure recorded")
                if (provider, code) not in environment_keys:
                    environment_errors.append({
                        "code": f"{provider}:{code}",
                        "message": message,
                        "evidenceReferences": [reference],
                    })
                    environment_keys.add((provider, code))
        availability = report.get("tableAvailability")
        if isinstance(availability, dict):
            for table, item in availability.items():
                if isinstance(item, dict) and item.get("available") is False:
                    shared_failure = True
                    code = f"tableUnavailable:{table}"
                    if (provider, code) not in environment_keys:
                        environment_errors.append({
                            "code": f"{provider}:{code}",
                            "message": str(item.get("error") or f"Provider report marks {table} unavailable"),
                            "evidenceReferences": [reference],
                        })
                        environment_keys.add((provider, code))
        entries = report.get("results")
        if not isinstance(entries, list):
            raise ValueError(f"existing {provider} runtime report has no results list")
        names: set[str] = set()
        waived_source_failures: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"existing {provider} runtime report contains a malformed result")
            detection = str(entry.get("detection") or "").replace("\\", "/")
            if detection in names:
                raise ValueError(f"existing {provider} runtime report duplicates {detection}")
            names.add(detection)
            rule_id = detection_to_rule.get(detection)
            if rule_id is None:
                raise ValueError(f"existing {provider} runtime report contains unknown detection {detection}")
            expected = expected_hashes[detection][provider]
            query_hash = entry.get("querySha256")
            if not expected or query_hash != expected:
                raise ValueError(
                    f"stale {provider} query hash for {detection}; refresh current results before continuing"
                )
            status = str(entry.get("status") or "").lower()
            if status == "passed":
                continue
            all_reports_passed = False
            if status == "not-run":
                continue
            if status not in {"failed", "blocked"}:
                raise ValueError(f"invalid {provider} result status {status!r} for {detection}")
            if status == "blocked" and shared_failure:
                continue
            source_whitelist_match = None
            if (
                status == "failed"
                and provider in SOURCE_PROVIDERS
                and report.get("querySurface") in (
                    None,
                    SOURCE_PROVIDERS[provider],
                )
                and not report.get("providerFallback")
                and report.get("familyComplete") is not False
                and not shared_failure
            ):
                source_whitelist_match = missing_schema_whitelist_match(
                    entry,
                    provider=provider,
                    expected_query_sha256=expected,
                )
            if source_whitelist_match:
                waived_source_failures.append(
                    (rule_id, entry, source_whitelist_match)
                )
                continue
            message = str(entry.get("error") or f"{provider} reported {status}")
            runtime_findings[rule_id].append({
                "findingId": f"runtime-{provider}-{len(runtime_findings[rule_id]) + 1}",
                "kind": "error",
                "message": message,
                "unresolved": True,
                "evidenceReferences": [reference],
            })
        if names != set(detection_to_rule):
            all_reports_passed = False
        if report.get("familyComplete") is False:
            all_reports_passed = False
        family_is_complete = (
            names == set(detection_to_rule)
            and report.get("familyComplete") is not False
            and not shared_failure
            and not report.get("providerFallback")
            and report.get("querySurface")
            in (None, SOURCE_PROVIDERS.get(provider))
        )
        for rule_id, entry, match in waived_source_failures:
            if family_is_complete:
                finding_id = (
                    f"runtime-whitelist-{provider}-"
                    f"{len(runtime_findings[rule_id]) + 1}"
                )
                runtime_findings[rule_id].append({
                    "findingId": finding_id,
                    "kind": "error",
                    "message": (
                        f"Source query is source-waived for {match['table']}: "
                        f"{match['reason']} Raw provider status remains "
                        f"{entry.get('status')!r}: {entry.get('error')!s}"
                    ),
                    "unresolved": False,
                    "evidenceReferences": [reference],
                })
            else:
                runtime_findings[rule_id].append({
                    "findingId": (
                        f"runtime-{provider}-"
                        f"{len(runtime_findings[rule_id]) + 1}"
                    ),
                    "kind": "error",
                    "message": str(
                        entry.get("error")
                        or f"{provider} reported {entry.get('status')}"
                    ),
                    "unresolved": True,
                    "evidenceReferences": [reference],
                })
    if not expected_hashes:
        all_reports_passed = False
    return runtime_findings, environment_errors, all_reports_passed


def _conversion_contract_results(
    root: Path,
    run_directory: Path,
    inventory: list[dict[str, Any]],
    conversion: dict[str, Any],
    validation: dict[str, Any],
    previous_record: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    _, analytic, output = solution_paths(root)
    scope = conversion.get("scope") or {}
    if (
        scope.get("kind") != "solution"
        or scope.get("sourceTotal") != len(inventory)
        or scope.get("selectedTotal") != len(inventory)
        or len(conversion.get("results") or []) != len(inventory)
    ):
        raise ValueError("conversion results do not cover the frozen full source inventory")
    conversion_by_path: dict[str, dict[str, Any]] = {}
    for item in conversion["results"]:
        source_path = str(item.get("sourceRelativePath") or "").replace("\\", "/")
        if source_path in conversion_by_path:
            raise ValueError(f"conversion results duplicate source path: {source_path}")
        conversion_by_path[source_path] = item
    expected_sources = {rule["path"] for rule in inventory}
    if set(conversion_by_path) != expected_sources:
        raise ValueError(
            "conversion result paths do not match the frozen inventory "
            f"(missing={sorted(expected_sources - set(conversion_by_path))}, "
            f"extra={sorted(set(conversion_by_path) - expected_sources)})"
        )

    validation_by_path: dict[str, dict[str, Any]] = {}
    for item in validation.get("results") or []:
        try:
            target_path = Path(item["file"]).expanduser().resolve()
            relative = target_path.relative_to(root).as_posix()
        except (KeyError, OSError, ValueError) as exc:
            raise ValueError("structural validation returned an invalid target path") from exc
        if relative in validation_by_path:
            raise ValueError(f"structural validation duplicates target path: {relative}")
        validation_by_path[relative] = item

    manifest_path = run_directory / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("full conversion did not persist its current manifest")
    manifest_reference = _reference_for_file(root, manifest_path, "other")
    previous_results = {
        item["ruleId"]: item for item in previous_record.get("results", [])
    }
    results: list[dict[str, Any]] = []
    output_source_prefix = output.relative_to(root).as_posix() + "/"
    analytic_prefix = analytic.relative_to(root).as_posix() + "/"
    for rule in inventory:
        source_path = rule["path"]
        prior = previous_results.get(rule["ruleId"], {})
        item = conversion_by_path[source_path]
        output_path = str(item.get("outputRelativePath") or "").replace("\\", "/")
        source_suffix = source_path[len(analytic_prefix):] if source_path.startswith(analytic_prefix) else None
        expected_output = output_source_prefix + source_suffix if source_suffix is not None else None
        if not expected_output or output_path != expected_output:
            raise ValueError(
                f"conversion output path conflicts with source inventory for {rule['ruleId']}"
            )
        conversion_status = item.get("status")
        if conversion_status not in {"converted", "needsReview", "conflict", "excluded"}:
            raise ValueError(f"unsupported conversion result for {rule['ruleId']}: {conversion_status!r}")
        error_messages = [str(value) for value in item.get("errors") or [] if str(value).strip()]
        review_messages = [
            str(value) for value in item.get("reviewReasons") or [] if str(value).strip()
        ]
        warning_messages = [
            str(value) for value in item.get("warnings") or [] if str(value).strip()
        ]
        mapping_assumptions = list(prior.get("mappingAssumptions") or [])
        mapping_assumptions.extend(
            reason for reason in review_messages
            if reason.startswith(BEST_EFFORT_ENTITY_REVIEW_PREFIX)
            and reason not in mapping_assumptions
        )
        if conversion_status == "needsReview" and not error_messages:
            error_messages.extend(review_messages or ["Conversion is blocked pending technical review"])
        elif conversion_status == "conflict" and not error_messages:
            error_messages.append("Conversion reported an artifact or identity conflict")
        elif conversion_status == "excluded":
            error_messages.append("Source rule was excluded; full-solution scope is not complete")

        target_path = content_path(root, output_path)
        target: dict[str, Any] | None = None
        structural = validation_by_path.get(output_path)
        target_document: dict[str, Any] | None = None
        if conversion_status in {"converted", "needsReview"} and target_path.is_file():
            target_bytes = target_path.read_bytes()
            target_digest = hashlib.sha256(target_bytes).hexdigest()
            previous_target = prior.get("target")
            if previous_target and previous_target.get("sha256") != target_digest:
                raise ValueError(
                    f"generated target changed since its prior YOLO result: {output_path}; "
                    "preserve the edit and reconcile in a new run"
                )
            try:
                target_document = yaml.safe_load(target_bytes.decode("utf-8-sig")) or {}
            except (UnicodeError, yaml.YAMLError) as exc:
                error_messages.append(f"generated target YAML is invalid: {exc}")
            if not isinstance(target_document, dict):
                error_messages.append("generated target must be a YAML object")
                target_document = None
            provenance = (
                ((target_document.get("contentProvenance") or {}).get("source") or {})
                if target_document else {}
            )
            if (
                provenance.get("path") != source_path
                or str(provenance.get("id") or "").casefold() != rule["ruleId"].casefold()
            ):
                error_messages.append("generated target provenance conflicts with frozen source identity")
            query_text = (
                ((target_document.get("properties") or {}).get("queryCondition") or {}).get("queryText")
                if target_document else None
            )
            if not isinstance(query_text, str) or not query_text.strip():
                error_messages.append("generated target has no Advanced Hunting query")
                query_hash = None
            else:
                query_hash = hashlib.sha256(query_text.encode("utf-8")).hexdigest()
            structurally_valid = bool(structural and structural.get("valid") is True)
            target = {
                "path": output_path,
                "sha256": target_digest,
                "querySha256": query_hash,
                "structurallyValid": structurally_valid,
            }
            if not structural:
                error_messages.append("generated target has no structural validation result")
            elif not structurally_valid:
                error_messages.extend(str(value) for value in structural.get("errors") or [])
        else:
            if conversion_status in {"converted", "needsReview"}:
                error_messages.append("conversion target is missing")
            elif target_path.exists() and target_path.is_symlink():
                raise ValueError(f"conversion target path is an unsafe symlink: {output_path}")

        errors = list(dict.fromkeys(message for message in error_messages if message.strip()))
        valid_target = target is not None and target["structurallyValid"]
        status = "migrated" if conversion_status == "converted" and valid_target and not errors else "blocked"
        disposition = "normal" if status == "migrated" else "authoringBlocked"
        finding_records: list[dict[str, Any]] = []
        for index, message in enumerate(errors, 1):
            finding_records.append({
                "findingId": f"authoring-error-{index}",
                "kind": "error",
                "message": message,
                "unresolved": True,
                "evidenceReferences": [manifest_reference],
            })
        for index, message in enumerate(warning_messages, 1):
            finding_records.append({
                "findingId": f"conversion-warning-{index}",
                "kind": "warning",
                "message": message,
                "unresolved": False,
                "evidenceReferences": [manifest_reference],
            })
        if conversion_status == "converted" and item.get("reviewRequired") is True:
            for index, message in enumerate(review_messages, 1):
                finding_records.append({
                    "findingId": f"review-pending-{index}",
                    "kind": "warning",
                    "message": message,
                    "unresolved": False,
                    "evidenceReferences": [manifest_reference],
                })
        target_references = (
            [{
                "path": target["path"],
                "sha256": target["sha256"],
                "kind": "generatedTarget",
            }]
            if target else []
        )
        results.append({
            "ruleId": rule["ruleId"],
            "sourceSha256": rule["sha256"],
            "status": status,
            "conversionStatus": conversion_status,
            "validationStatus": (
                "passed" if structural and structural.get("valid") is True
                else "failed" if structural else "notRun"
            ),
            "deploymentDisposition": disposition,
            "target": target,
            "reviewRequired": bool(item.get("reviewRequired")),
            "mappingAssumptions": mapping_assumptions,
            "findings": finding_records,
            "qualificationStatus": "untested",
            "qualificationEvidenceReferences": [],
            "evidenceReferences": [manifest_reference, *target_references],
        })

    runtime_findings, environment_errors, _ = _runtime_observations(
        root, run_directory, inventory, results
    )
    for result in results:
        additional = runtime_findings[result["ruleId"]]
        if not additional:
            continue
        result["findings"].extend(additional)
        result["status"] = "blocked"
        result["deploymentDisposition"] = "authoringBlocked"
        for finding in additional:
            for reference in finding["evidenceReferences"]:
                if reference not in result["evidenceReferences"]:
                    result["evidenceReferences"].append(reference)
    return results, environment_errors


def _current_yolo_record(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    authoring = state.get("authoring")
    if not isinstance(authoring, dict) or authoring.get("mode") != "yolo":
        raise ValueError("this workflow was not explicitly initialized in YOLO mode")
    reference = authoring["currentContract"]
    document, content = _load_contract_snapshot(state_path.parent, reference)
    if document["inventory"]["sha256"] != authoring["inventorySha256"]:
        raise ValueError("workflow state and authoring contract inventory hashes differ")
    _verify_source_inventory(solution, document)
    _verify_target_hashes(solution, document)
    return document, content


def read_authoring_contract(solution: str | Path) -> dict[str, Any]:
    """Read only the exact content-addressed contract referenced by selected workflow state."""
    root = Path(solution).expanduser().resolve()
    path, state = _load(root)
    if not state.get("authoring"):
        raise ValueError("selected workflow has no explicit YOLO authoring contract")
    document, _ = _load_contract_snapshot(path.parent, state["authoring"]["currentContract"])
    if document["runId"] != state.get("runId"):
        raise ValueError("authoring contract is bound to a different workflow run")
    return document


def _verify_target_hashes(solution: Path, document: dict[str, Any]) -> None:
    for result in document["results"]:
        target = result.get("target")
        if target is None:
            continue
        path = content_path(solution, target["path"])
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"previously recorded target is missing or unsafe: {target['path']}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != target["sha256"]:
            raise ValueError(
                f"generated target hash is stale: {target['path']}; preserve user edits and start a new run"
            )


def _validate_current_yolo_targets(
    solution: Path,
    record: dict[str, Any],
) -> None:
    root = solution.expanduser().resolve()
    inventory = record.get("inventory", {}).get("rules") or []
    results = record.get("results") or []
    results_by_id = {
        item.get("ruleId"): item
        for item in results
        if isinstance(item, dict)
    }
    inventory_by_id = {
        item.get("ruleId"): item
        for item in inventory
        if isinstance(item, dict)
    }
    if (
        not inventory_by_id
        or len(inventory_by_id) != len(inventory)
        or set(results_by_id) != set(inventory_by_id)
        or len(results_by_id) != len(results)
    ):
        raise ValueError(
            "source-waived validation requires current YOLO results for the complete source inventory"
        )

    _verify_target_hashes(root, record)
    expected_outputs: set[str] = set()
    for rule_id, rule in inventory_by_id.items():
        source_path = str(rule.get("path") or "").replace("\\", "/")
        source_parts = Path(source_path).parts
        if (
            len(source_parts) < 2
            or source_parts[0].casefold() not in {"analytic rules", "analytics rules"}
        ):
            raise ValueError(
                "source-waived validation requires safe full-inventory YOLO source paths"
            )
        expected_output = (
            Path("XDR Detections") / Path(*source_parts[1:])
        ).as_posix()
        expected_outputs.add(expected_output)
        result = results_by_id[rule_id]
        target = result.get("target")
        if not isinstance(target, dict) or target.get("path") != expected_output:
            raise ValueError(
                "source-waived validation requires a current generated target for every YOLO inventory rule"
            )
        target_path = content_path(root, expected_output)
        try:
            document = yaml.safe_load(target_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ValueError(
                f"current YOLO target is unreadable or invalid: {expected_output}"
            ) from exc
        if not isinstance(document, dict):
            raise ValueError(f"current YOLO target is not a YAML object: {expected_output}")
        provenance = document.get("contentProvenance") or {}
        source = provenance.get("source") or {}
        conversion = provenance.get("conversion") or {}
        if (
            source.get("path") != source_path
            or source.get("id") != rule_id
            or source.get("querySha256") != rule.get("querySha256")
            or conversion.get("status") != "converted"
            or conversion.get("reviewRequired") is not False
            or conversion.get("errors") not in ([], None)
        ):
            raise ValueError(
                "source-waived validation is blocked by current YOLO target provenance, "
                "conversion errors, or review requirements"
            )
        structural_errors = validate_document(document)
        if structural_errors:
            raise ValueError(
                "source-waived validation is blocked by current YOLO target technical errors: "
                + "; ".join(structural_errors)
            )

    current_outputs = {
        path.relative_to(root).as_posix()
        for path in xdr_detection_files(root / "XDR Detections")
    }
    if current_outputs != expected_outputs:
        raise ValueError(
            "source-waived validation requires current YOLO targets to match the complete source inventory"
        )


def _refresh_yolo_record_unlocked(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
    previous_record: dict[str, Any],
) -> tuple[dict[str, Any], bool, dict[str, Any]]:
    _verify_target_hashes(solution, previous_record)
    inventory = previous_record["inventory"]["rules"]
    results = json.loads(json.dumps(previous_record["results"]))
    for result in results:
        result["findings"] = [
            finding for finding in result["findings"]
            if not finding["findingId"].startswith("runtime-")
        ]
        result["evidenceReferences"] = [
            reference for reference in result["evidenceReferences"]
            if reference["kind"] != "runtimeVerification"
        ]
        unresolved = any(
            finding["kind"] == "error" and finding["unresolved"]
            for finding in result["findings"]
        )
        if (
            result.get("conversionStatus") == "converted"
            and result.get("validationStatus") == "passed"
            and (result.get("target") or {}).get("structurallyValid") is True
            and not unresolved
        ):
            result["status"] = "migrated"
            result["deploymentDisposition"] = "normal"
        elif result["status"] != "suppressed":
            result["status"] = "blocked" if unresolved or result.get("target") else "unprocessed"
            result["deploymentDisposition"] = (
                "authoringBlocked" if result["status"] == "blocked" else "normal"
            )

    runtime_findings, environment_errors, _ = _runtime_observations(
        solution, state_path.parent, inventory, results
    )
    for result in results:
        findings = runtime_findings[result["ruleId"]]
        if findings:
            result["findings"].extend(findings)
            if any(
                finding.get("kind") == "error"
                and finding.get("unresolved") is True
                for finding in findings
            ):
                result["status"] = "blocked"
                result["deploymentDisposition"] = "authoringBlocked"
            for finding in findings:
                for reference in finding["evidenceReferences"]:
                    if reference not in result["evidenceReferences"]:
                        result["evidenceReferences"].append(reference)

    current_reference = state["authoring"]["currentContract"]
    if (
        results == previous_record["results"]
        and environment_errors == previous_record["environmentErrors"]
    ):
        return previous_record, False, environment_errors
    core = _contract_core(
        solution,
        state_path.parent.name,
        inventory,
        revision=current_reference["revision"] + 1,
        previous_sha256=current_reference["sha256"],
        results=results,
        environment_errors=environment_errors,
    )
    record, digest = _persist_contract_snapshot(state_path.parent, state, core)
    coverage = record["coverage"]
    authoring = state["authoring"]
    if coverage["stopThresholdReached"] and authoring["status"] == "active":
        authoring["status"] = "stopped"
        authoring["stopReason"] = (
            f"Durable rule-error threshold reached: {coverage['E']}/{coverage['N']} "
            "(100*E > 50*N)."
        )
        state["workflowStatus"] = "blocked"
    elif authoring["status"] == "stopped":
        state["workflowStatus"] = "blocked"
    _write_unlocked(state_path, state)
    return record, True, environment_errors


def refresh_yolo_authoring(solution: str | Path) -> dict[str, Any]:
    """Import current hash-bound provider reports without rerunning conversion or validation."""
    root = Path(solution).expanduser().resolve()
    with _state_writer_lock(root) as state_path:
        path, state = _load(root)
        if path != state_path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        with using_run(root, state["runId"]):
            state = _recover_yolo_state(root, path, state)
            if state["authoring"]["status"] == "conflicted":
                raise ValueError("conflicted YOLO runs cannot be refreshed")
            previous, _ = _current_yolo_record(root, path, state)
            record, updated, environment_errors = _refresh_yolo_record_unlocked(
                root, path, state, previous
            )
            state = _load(root)[1]
            if state["authoring"]["status"] == "active":
                state = _complete_runtime_pending_stage(root, path, state, record)
            return {
                "runId": state["runId"],
                "status": state["authoring"]["status"],
                "authoringContract": state["authoring"]["currentContract"],
                "coverage": record["coverage"],
                "environmentErrorCount": len(environment_errors),
                "updated": updated,
                "workflowStatus": state["workflowStatus"],
                "next": _next_stage_name(state),
            }


def _mark_yolo_conflicted(
    state_path: Path,
    state: dict[str, Any],
    reason: str,
) -> None:
    state["authoring"]["status"] = "conflicted"
    state["authoring"]["stopReason"] = reason
    state["workflowStatus"] = "blocked"
    _write_unlocked(state_path, state)


def _read_full_conversion_manifest(
    root: Path,
    run_directory: Path,
    inventory: list[dict[str, Any]],
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    manifest_path = run_directory / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("full-solution conversion manifest is missing or unsafe")
    content = manifest_path.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if expected_sha256 and digest != expected_sha256:
        raise ValueError("conversion manifest hash changed after its workflow stage")
    try:
        document = json.loads(content)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"full-solution conversion manifest is invalid: {exc}") from exc
    scope = document.get("scope") or {}
    if (
        scope.get("kind") != "solution"
        or scope.get("sourceTotal") != len(inventory)
        or scope.get("selectedTotal") != len(inventory)
        or len(document.get("results") or []) != len(inventory)
    ):
        raise ValueError("conversion manifest does not cover the frozen complete source inventory")
    return document


def _source_waiver_unrelated_blockers(record: dict[str, Any]) -> list[str]:
    blockers = []
    for result in record.get("results") or []:
        if (
            result.get("status") != "migrated"
            or result.get("conversionStatus") != "converted"
            or result.get("validationStatus") != "passed"
            or result.get("reviewRequired") is True
            or (result.get("target") or {}).get("structurallyValid") is not True
            or any(
                isinstance(finding, dict)
                and finding.get("unresolved") is True
                and finding.get("kind") in {"error", "review"}
                for finding in result.get("findings") or []
            )
        ):
            blockers.append(str(result.get("ruleId") or "<unknown>"))
    return blockers


def _validate_source_waiver_conversion_gates(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
) -> None:
    if any(
        state["stages"][stage].get("status") != "passed"
        for stage in ("discovery", "conversion")
    ):
        raise ValueError(
            "source-waived validation requires passed discovery and full-solution conversion stages"
        )
    conversion_stage = state["stages"]["conversion"]

    if state.get("authoring"):
        record, _ = _current_yolo_record(solution, state_path, state)
        _validate_current_yolo_targets(solution, record)
        blockers = _source_waiver_unrelated_blockers(record)
        if blockers:
            raise ValueError(
                "source-waived validation is blocked by unrelated technical or review gates: "
                + ", ".join(blockers)
            )
        return

    manifest_path = state_path.parent / "manifest.json"
    conversion_artifacts = conversion_stage.get("artifacts")
    expected_hash = (
        conversion_artifacts.get("manifestSha256")
        if isinstance(conversion_artifacts, dict)
        else None
    )
    if not manifest_path.is_file() or not isinstance(expected_hash, str):
        raise ValueError(
            "source-waived validation requires a current full-solution conversion manifest"
        )
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_hash:
        raise ValueError("source-waived validation conversion manifest is stale")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("source-waived validation conversion manifest is invalid") from exc
    scope = manifest.get("scope") if isinstance(manifest, dict) else None
    results = manifest.get("results") if isinstance(manifest, dict) else None
    total = manifest.get("total") if isinstance(manifest, dict) else None
    if (
        not isinstance(scope, dict)
        or scope.get("kind") != "solution"
        or type(total) is not int
        or total < 1
        or scope.get("sourceTotal") != total
        or scope.get("selectedTotal") != total
        or not isinstance(results, list)
        or len(results) != total
        or manifest.get("converted") != total
        or manifest.get("excluded") != 0
        or manifest.get("needsReview") != 0
        or manifest.get("reviewRequired") != 0
        or manifest.get("conflicts") != 0
    ):
        raise ValueError(
            "source-waived validation requires complete, technically clean full-solution conversion"
        )

    root = solution.expanduser().resolve()
    expected_outputs: set[str] = set()
    for item in results:
        if (
            not isinstance(item, dict)
            or item.get("status") != "converted"
            or item.get("reviewRequired") is not False
            or item.get("errors") not in ([], None)
        ):
            raise ValueError(
                "source-waived validation is blocked by unrelated conversion or review findings"
            )
        source_reference = str(item.get("sourceRelativePath") or "").replace("\\", "/")
        output_reference = str(item.get("outputRelativePath") or "").replace("\\", "/")
        parts = Path(source_reference).parts
        if (
            len(parts) < 2
            or parts[0].casefold() not in {"analytic rules", "analytics rules"}
            or output_reference != (Path("XDR Detections") / Path(*parts[1:])).as_posix()
            or output_reference in expected_outputs
        ):
            raise ValueError(
                "source-waived validation conversion manifest has incomplete or conflicting output paths"
            )
        expected_outputs.add(output_reference)
        target_path = content_path(root, output_reference)
        if not target_path.is_file() or target_path.is_symlink():
            raise ValueError(
                "source-waived validation conversion target is missing or unsafe"
            )
        try:
            document = yaml.safe_load(target_path.read_text(encoding="utf-8-sig")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError("source-waived validation conversion target is invalid") from exc
        conversion = (
            ((document.get("contentProvenance") or {}).get("conversion") or {})
            if isinstance(document, dict)
            else {}
        )
        if (
            not isinstance(conversion, dict)
            or conversion.get("status") != "converted"
            or conversion.get("reviewRequired") is not False
            or conversion.get("errors") not in ([], None)
        ):
            raise ValueError(
                "source-waived validation is blocked by current Custom Detection review or conversion findings"
            )

    output_directory = root / "XDR Detections"
    current_outputs = {
        path.relative_to(root).as_posix()
        for path in xdr_detection_files(output_directory)
    }
    if current_outputs != expected_outputs:
        raise ValueError(
            "source-waived validation requires conversion targets to match the full manifest inventory"
        )
    structural = validate_solution(root)
    if (
        structural.get("conversionScope", {}).get("kind") != "solution"
        or structural.get("total") != total
        or structural.get("invalid") != 0
        or len(structural.get("results") or []) != total
        or any(item.get("valid") is not True for item in structural.get("results") or [])
    ):
        raise ValueError(
            "source-waived validation requires current full-solution structural validation to pass"
        )


def _current_runtime_status(
    solution: Path,
    profile: str,
    record: dict[str, Any],
) -> tuple[str, str | None, dict[str, Any]]:
    from .runtime import current_runtime_evidence

    evidence = current_runtime_evidence(solution)
    if (
        evidence.get("sourceWhitelist")
        and not evidence.get("sourceWaiverOnlyBlocker")
    ):
        return (
            "blocked",
            "The IdentityInfo source failure is visible as source-waived, but XDR runtime "
            "or another exact validation gate is incomplete; validation stays blocked.",
            evidence,
        )
    if evidence.get("sourceWaiverOnlyBlocker"):
        unrelated_blockers = _source_waiver_unrelated_blockers(record)
        if unrelated_blockers:
            return (
                "blocked",
                "Source waiver is recorded, but unrelated technical or review gates remain; validation stays blocked.",
                evidence,
            )
        return (
            "source-waived",
            "Validation completed with the built-in IdentityInfo source-table whitelist. "
            "The raw Sentinel query result remains failed; this run is not fully runtime-qualified.",
            evidence,
        )
    if evidence.get("passed"):
        return "passed", None, evidence
    if any(
        result["status"] != "migrated"
        for result in record["results"]
    ):
        return "blocked", "YOLO rule-level technical blockers remain; see the authoring contract.", evidence
    if (
        profile == "authoring"
        and record["environmentErrors"]
        and not evidence.get("currentQueryFailures")
    ):
        return (
            "environment-blocked",
            "Runtime validation is blocked by provider/environment evidence; no KQL/runtime query failure was relabeled.",
            evidence,
        )
    return (
        "not-run",
        "Runtime validation is not complete; exact current-query provider evidence is missing or blocked.",
        evidence,
    )


def _source_whitelist_stage_artifacts(
    runtime_evidence: dict[str, Any],
) -> dict[str, str]:
    entries = runtime_evidence.get("sourceWhitelist")
    if not isinstance(entries, list) or not entries:
        return {}
    summary = [
        {
            "detection": item.get("detection"),
            "table": item.get("table"),
            "status": item.get("status"),
            "applied": item.get("applied") is True,
            "querySha256": item.get("querySha256"),
            "reason": item.get("reason"),
            "rawStatus": (item.get("rawFailure") or {}).get("status"),
            "rawStatusCode": (item.get("rawFailure") or {}).get("statusCode"),
            "rawFailureKind": (item.get("rawFailure") or {}).get("failureKind"),
        }
        for item in entries
        if isinstance(item, dict)
    ]
    return {
        "sourceRuntimeWhitelistTable": "IdentityInfo",
        "sourceRuntimeWhitelistCount": str(len(summary)),
        "sourceRuntimeWhitelistStatus": (
            "source-waived"
            if summary and all(item["applied"] for item in summary)
            else "candidate-blocked"
        ),
        "sourceRuntimeWhitelist": json.dumps(
            summary, sort_keys=True, separators=(",", ":")
        ),
    }


def _complete_runtime_pending_stage(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    stage = state["stages"]["validation"]
    if not (
        stage["status"] == "blocked"
        and str(stage.get("message") or "").startswith("Runtime validation is not complete")
    ):
        return state
    status, message, runtime_evidence = _current_runtime_status(
        solution, state["context"]["workflowProfile"], record
    )
    if status not in {"passed", "environment-blocked", "source-waived"}:
        return state
    if status == "source-waived":
        _validate_source_waiver_conversion_gates(solution, state_path, state)
        whitelist = runtime_evidence.get("sourceWhitelist") or []
        if not whitelist or any(
            item.get("table") != "IdentityInfo"
            or item.get("rawFailure", {}).get("status") != "failed"
            or item.get("applied") is not True
            for item in whitelist
        ):
            return state
    _start_workflow_stage_unlocked(solution, "validation", state_path)
    artifacts = (
        {"runtimeStatus": status}
        if status in {"environment-blocked", "source-waived"}
        else {}
    )
    if status == "source-waived":
        artifacts.update(_source_whitelist_stage_artifacts(runtime_evidence))
        artifacts["sourceRuntimeWhitelistRawStatus"] = "failed"
    _complete_workflow_stage_unlocked(
        solution,
        "validation",
        state_path,
        status="passed",
        message=message,
        artifacts=artifacts,
        evidence=None,
    )
    return _load(solution)[1]


def run_yolo_authoring(solution: str | Path) -> dict[str, Any]:
    """Run existing local discovery/conversion/validation once under the frozen YOLO contract."""
    root = Path(solution).expanduser().resolve()
    with _state_writer_lock(root) as state_path:
        loaded_path, state = _load(root)
        if loaded_path != state_path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        run_id = state.get("runId")
        if not run_id:
            raise ValueError("YOLO authoring requires an explicitly initialized run-scoped workflow")
        with using_run(root, run_id):
            state = _recover_yolo_state(root, state_path, state)
            if not state.get("authoring") or state["authoring"]["mode"] != "yolo":
                raise ValueError("workflow was not explicitly initialized with --yolo")
            record, _ = _current_yolo_record(root, state_path, state)
            authoring = state["authoring"]
            budget = state.get("budget")
            if not isinstance(budget, dict):
                raise ValueError(
                    "YOLO workflow has no durable campaign budget; initialize or explicitly "
                    "link it with workflow-init --yolo --campaign-id"
                )
            if (
                authoring["status"] in {"stopped", "conflicted"}
                and not str(authoring.get("stopReason") or "").startswith("Campaign budget:")
            ):
                return {
                    "runId": run_id,
                    "status": authoring["status"],
                    "reason": authoring.get("stopReason"),
                    "coverage": record["coverage"],
                    "authoringContract": authoring["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": False,
                }
            if budget.get("status") == "stopped":
                return {
                    "runId": run_id,
                    "status": "budget-exhausted",
                    "reason": budget.get("stopReason"),
                    "coverage": record["coverage"],
                    "authoringContract": authoring["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": False,
                }
            if authoring["status"] in {"stopped", "conflicted"}:
                return {
                    "runId": run_id,
                    "status": authoring["status"],
                    "reason": authoring.get("stopReason"),
                    "coverage": record["coverage"],
                    "authoringContract": authoring["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": False,
                }

            inventory = _verify_source_inventory(root, record)
            inventory_hash = record["inventory"]["sha256"]
            if state["context"].get("profileSelectionConfirmed") is not True:
                raise ValueError("YOLO requires explicit Authoring or Qualification profile selection")
            if state["context"]["workflowProfile"] == "qualification" and not state["context"].get("targetContextLocked"):
                raise ValueError("Qualification YOLO requires its existing locked target")

            if any(
                state["stages"][stage_name]["status"] != "passed"
                for stage_name in ("discovery", "conversion", "validation")
            ):
                try:
                    ensure_work_available(
                        root,
                        budget["campaignId"],
                        inventory_sha256=inventory_hash,
                    )
                except BudgetError as exc:
                    next_stage = next(
                        name for name in ("discovery", "conversion", "validation")
                        if state["stages"][name]["status"] != "passed"
                    )
                    _stop_budget_run(state_path, state, next_stage, str(exc))
                    return {
                        "runId": run_id,
                        "status": "budget-exhausted",
                        "reason": str(exc),
                        "coverage": record["coverage"],
                        "authoringContract": state["authoring"]["currentContract"],
                        "workflowStatus": state["workflowStatus"],
                        "next": None,
                        "resumed": True,
                        "workPerformed": False,
                    }

            discovery = state["stages"]["discovery"]
            if discovery["status"] != "passed":
                if discovery["status"] != "running":
                    _start_workflow_stage_unlocked(root, "discovery", state_path)
                discovery_dispatched = False
                try:
                    with measured_operation(
                        root,
                        budget["campaignId"],
                        inventory_sha256=inventory_hash,
                        run_id=run_id,
                        dimension="workflowDiscovery",
                    ):
                        discovery_dispatched = True
                        inspection = inspect_solution(root)
                except BudgetError as exc:
                    if discovery_dispatched:
                        raise
                    current_state = _load(root)[1]
                    _stop_budget_run(state_path, current_state, "discovery", str(exc))
                    return {
                        "runId": run_id,
                        "status": "budget-exhausted",
                        "reason": str(exc),
                        "coverage": record["coverage"],
                        "authoringContract": current_state["authoring"]["currentContract"],
                        "workflowStatus": current_state["workflowStatus"],
                        "next": None,
                        "resumed": discovery["status"] == "running",
                        "workPerformed": False,
                    }
                if inspection["analyticRuleCount"] != len(inventory):
                    _mark_yolo_conflicted(
                        state_path, state,
                        "Discovery inventory count changed after YOLO scope freeze.",
                    )
                    raise ValueError("discovery inventory changed after YOLO scope freeze")
                _complete_workflow_stage_unlocked(
                    root,
                    "discovery",
                    state_path,
                    status="passed",
                    message="Complete recursive source inventory verified against frozen YOLO scope.",
                    artifacts={"sourceInventorySha256": inventory_hash},
                )
                state = _load(root)[1]

            conversion_stage = state["stages"]["conversion"]
            if conversion_stage["status"] == "passed":
                expected_manifest_hash = conversion_stage["artifacts"].get("manifestSha256")
                conversion = _read_full_conversion_manifest(
                    root, state_path.parent, inventory, expected_manifest_hash
                )
            else:
                if conversion_stage["status"] != "running":
                    _start_workflow_stage_unlocked(root, "conversion", state_path)
                conversion_dispatched = False
                try:
                    with measured_operation(
                        root,
                        budget["campaignId"],
                        inventory_sha256=inventory_hash,
                        run_id=run_id,
                        dimension="conversionPass",
                    ):
                        conversion_dispatched = True
                        conversion = convert_solution(root)
                    _verify_source_inventory(root, record)
                    manifest = _read_full_conversion_manifest(
                        root, state_path.parent, inventory
                    )
                except BudgetError as exc:
                    if conversion_dispatched:
                        current_path, current_state = _load(root)
                        stage = current_state["stages"]["conversion"]
                        if stage["status"] == "running":
                            _complete_workflow_stage_unlocked(
                                root, "conversion", state_path, status="failed",
                                message=f"Conversion ran but its budget receipt failed: {exc}",
                            )
                        return {
                            "runId": run_id,
                            "status": "failed",
                            "reason": str(exc),
                            "coverage": record["coverage"],
                            "authoringContract": current_state["authoring"]["currentContract"],
                            "workflowStatus": current_state["workflowStatus"],
                            "next": _next_stage_name(current_state),
                            "resumed": conversion_stage["status"] == "running",
                            "workPerformed": True,
                        }
                    current_path, current_state = _load(root)
                    if current_path != state_path:
                        raise ValueError("workflow state selection changed during budget check") from exc
                    _stop_budget_run(state_path, current_state, "conversion", str(exc))
                    return {
                        "runId": run_id,
                        "status": "budget-exhausted",
                        "reason": str(exc),
                        "coverage": record["coverage"],
                        "authoringContract": current_state["authoring"]["currentContract"],
                        "workflowStatus": current_state["workflowStatus"],
                        "next": None,
                        "resumed": conversion_stage["status"] == "running",
                        "workPerformed": False,
                    }
                except (OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
                    current_path, current_state = _load(root)
                    if current_path != state_path:
                        raise ValueError("workflow state selection changed during conversion") from exc
                    stage = current_state["stages"]["conversion"]
                    if stage["status"] == "running":
                        _complete_workflow_stage_unlocked(
                            root, "conversion", state_path, status="failed",
                            message=f"Full-solution conversion did not complete: {exc}",
                        )
                    return {
                        "runId": run_id,
                        "status": "failed",
                        "reason": str(exc),
                        "coverage": record["coverage"],
                        "authoringContract": current_state["authoring"]["currentContract"],
                        "workflowStatus": current_state["workflowStatus"],
                        "next": _next_stage_name(current_state),
                        "resumed": conversion_stage["status"] == "running",
                        "workPerformed": True,
                    }
                conversion = manifest
                conversion_sha256 = hashlib.sha256(
                    (state_path.parent / "manifest.json").read_bytes()
                ).hexdigest()
                state = _load(root)[1]
                _complete_workflow_stage_unlocked(
                    root,
                    "conversion",
                    state_path,
                    status="passed",
                    message=(
                        "Existing deterministic converter completed the full frozen source inventory; "
                        "per-rule technical outcomes remain in the authoring contract."
                    ),
                    artifacts={
                        "manifest": "manifest.json",
                        "manifestSha256": conversion_sha256,
                        "sourceInventorySha256": inventory_hash,
                    },
                )
                state = _load(root)[1]

            validation_stage = state["stages"]["validation"]
            if validation_stage["status"] == "passed":
                record, _ = _current_yolo_record(root, state_path, state)
                return {
                    "runId": run_id,
                    "status": state["authoring"]["status"],
                    "coverage": record["coverage"],
                    "authoringContract": state["authoring"]["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": False,
                }
            if (
                validation_stage["status"] == "blocked"
                and str(validation_stage.get("message") or "").startswith(
                    "Runtime validation is not complete"
                )
            ):
                refreshed = refresh_yolo_authoring(root)
                state = _load(root)[1]
                record, _ = _current_yolo_record(root, state_path, state)
                return {
                    "runId": run_id,
                    "status": state["authoring"]["status"],
                    "coverage": record["coverage"],
                    "authoringContract": state["authoring"]["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": bool(refreshed["updated"]),
                }
            if validation_stage["status"] == "blocked":
                record, _ = _current_yolo_record(root, state_path, state)
                return {
                    "runId": run_id,
                    "status": "blocked",
                    "reason": validation_stage.get("message"),
                    "coverage": record["coverage"],
                    "authoringContract": state["authoring"]["currentContract"],
                    "workflowStatus": state["workflowStatus"],
                    "next": _next_stage_name(state),
                    "resumed": True,
                    "workPerformed": False,
                }

            _start_workflow_stage_unlocked(root, "validation", state_path)
            state = _load(root)[1]
            validation_dispatched = False
            try:
                with measured_operation(
                    root,
                    budget["campaignId"],
                    inventory_sha256=inventory_hash,
                    run_id=run_id,
                    dimension="workflowValidation",
                ):
                    validation_dispatched = True
                    validation = validate_solution(root)
            except BudgetError as exc:
                if validation_dispatched:
                    current_state = _load(root)[1]
                    _complete_workflow_stage_unlocked(
                        root,
                        "validation",
                        state_path,
                        status="failed",
                        message=f"Validation ran but its budget receipt failed: {exc}",
                    )
                    return {
                        "runId": run_id,
                        "status": "failed",
                        "reason": str(exc),
                        "coverage": record["coverage"],
                        "authoringContract": current_state["authoring"]["currentContract"],
                        "workflowStatus": current_state["workflowStatus"],
                        "next": _next_stage_name(current_state),
                        "resumed": False,
                        "workPerformed": True,
                    }
                current_state = _load(root)[1]
                _stop_budget_run(state_path, current_state, "validation", str(exc))
                return {
                    "runId": run_id,
                    "status": "budget-exhausted",
                    "reason": str(exc),
                    "coverage": record["coverage"],
                    "authoringContract": current_state["authoring"]["currentContract"],
                    "workflowStatus": current_state["workflowStatus"],
                    "next": None,
                    "resumed": False,
                    "workPerformed": False,
                }
            _verify_source_inventory(root, record)
            results, environment_errors = _conversion_contract_results(
                root,
                state_path.parent,
                inventory,
                conversion,
                validation,
                record,
            )
            current_reference = state["authoring"]["currentContract"]
            core = _contract_core(
                root,
                run_id,
                inventory,
                revision=current_reference["revision"] + 1,
                previous_sha256=current_reference["sha256"],
                results=results,
                environment_errors=environment_errors,
            )
            new_record, _ = _persist_contract_snapshot(state_path.parent, state, core)
            coverage = new_record["coverage"]
            stopped = bool(coverage["stopThresholdReached"])
            if stopped:
                state["authoring"]["status"] = "stopped"
                state["authoring"]["stopReason"] = (
                    f"Durable rule-error threshold reached: {coverage['E']}/{coverage['N']} "
                    "(100*E > 50*N)."
                )
                state["workflowStatus"] = "blocked"
            _write_unlocked(state_path, state)

            if validation.get("conversionScope", {}).get("kind") == "rule":
                validation_status, message = "blocked", "Structural validation is scoped; full solution validation is required."
            elif validation["invalid"]:
                validation_status, message = "blocked", "One or more generated detections failed structural validation."
            elif any(result["status"] != "migrated" for result in new_record["results"]):
                validation_status, message = (
                    "blocked",
                    "YOLO rule-level technical blockers remain; inspect the per-rule authoring contract.",
                )
            elif stopped:
                validation_status, message = (
                    "blocked",
                    state["authoring"]["stopReason"],
                )
            else:
                validation_status, message, runtime_evidence = _current_runtime_status(
                    root, state["context"]["workflowProfile"], new_record
                )
                if validation_status == "not-run":
                    validation_status = "blocked"
            if validation_status == "environment-blocked":
                final_status = "passed"
                final_artifacts = {"runtimeStatus": "environment-blocked"}
            elif validation_status == "source-waived":
                final_status = "passed"
                whitelist = runtime_evidence.get("sourceWhitelist") or []
                final_artifacts = {
                    "runtimeStatus": "source-waived",
                    "sourceRuntimeWhitelistTable": "IdentityInfo",
                    "sourceRuntimeWhitelistCount": str(len(whitelist)),
                    "sourceRuntimeWhitelistRawStatus": "failed",
                }
            elif validation_status == "passed":
                final_status = "passed"
                final_artifacts = {}
            else:
                final_status = "blocked"
                final_artifacts = {"authoringContractSha256": state["authoring"]["currentContract"]["sha256"]}
            _complete_workflow_stage_unlocked(
                root,
                "validation",
                state_path,
                status=final_status,
                message=message,
                artifacts=final_artifacts,
                evidence=[state["authoring"]["currentContract"]["path"]],
            )
            state = _load(root)[1]
            record, _ = _current_yolo_record(root, state_path, state)
            return {
                "runId": run_id,
                "status": state["authoring"]["status"],
                "coverage": record["coverage"],
                "authoringContract": state["authoring"]["currentContract"],
                "workflowStatus": state["workflowStatus"],
                "next": _next_stage_name(state),
                "resumed": conversion_stage["status"] == "running",
                "workPerformed": True,
                "validationStatus": final_status,
                "runtimeStatus": validation_status,
                "packageAuthorized": False,
                "qualificationAuthorized": False,
                "prCreationAuthorized": False,
            }


def initialize_workflow(
    solution: str | Path,
    *,
    tenant_id: str | None = None,
    subscription_id: str | None = None,
    workspace_resource_id: str | None = None,
    workspace_customer_id: str | None = None,
    version_bump: str | None = None,
    workflow_profile: str | None = None,
    yolo: bool | None = None,
    campaign_id: str | None = None,
    new_run: bool = False,
) -> dict[str, Any]:
    root = Path(solution).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"solution folder does not exist: {root}")
    if version_bump not in (None, "none", "patch", "minor", "major"):
        raise ValueError("version bump must be none, patch, minor, or major")
    if workflow_profile is None:
        raise ValueError(
            "workflow profile selection is required: choose authoring or qualification"
        )
    if workflow_profile not in WORKFLOW_PROFILES:
        raise ValueError("workflow profile must be authoring or qualification")
    explicit_campaign_id = campaign_id
    if campaign_id is not None:
        from .budget import _safe_campaign_id
        campaign_id = _safe_campaign_id(campaign_id)
    if yolo is True and campaign_id is None and new_run:
        raise ValueError("new YOLO workflows require an explicit --campaign-id")
    target = None
    if workflow_profile == "qualification":
        missing = [
            name
            for name, value in (
                ("tenant-id", tenant_id),
                ("subscription-id", subscription_id),
                ("workspace-resource-id", workspace_resource_id),
                ("workspace-customer-id", workspace_customer_id),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                "qualification requires a locked target context: "
                + ", ".join(missing)
            )
        target = build_target(
            tenant_id=tenant_id or "",
            subscription_id=subscription_id or "",
            workspace_resource_id=workspace_resource_id or "",
            workspace_customer_id=workspace_customer_id or "",
        )
    requested_context = {
        "tenantId": target["tenantId"] if target else tenant_id,
        "subscriptionId": target["subscriptionId"] if target else subscription_id,
        "workspaceResourceId": (
            target["workspaceResourceId"] if target else workspace_resource_id
        ),
        "workspaceCustomerId": (
            target["workspaceCustomerId"] if target else workspace_customer_id
        ),
        "targetContextLocked": bool(target),
        "versionBump": version_bump,
    }
    if new_run:
        if requested_run_id(root):
            raise ValueError("--new-run and --run-id cannot be combined")
        _preflight_campaign_binding(
            root,
            campaign_id,
            yolo=yolo is True,
        )
        run = create_run(root)
        with using_run(root, run.name):
            return initialize_workflow(
                root, tenant_id=tenant_id, subscription_id=subscription_id,
                workspace_resource_id=workspace_resource_id,
                workspace_customer_id=workspace_customer_id, version_bump=version_bump,
                workflow_profile=workflow_profile, yolo=yolo, campaign_id=campaign_id,
            )
    existing_path = existing_artifact_path(root, STATE_FILE_NAME)
    if existing_path.exists():
        with _run_writer_lock(existing_path.parent):
            path, state = _load(root)
            if yolo is True and "authoring" not in state:
                raise ValueError(
                    "YOLO cannot be enabled on an existing legacy run; initialize a new run explicitly"
                )
            if yolo is True and not state.get("budget") and not campaign_id:
                raise ValueError(
                    "pre-existing YOLO run has unmeasured usage; provide "
                    "--campaign-id to link it conservatively"
                )
            context = state["context"]
            for key, value in requested_context.items():
                if key == "targetContextLocked":
                    continue
                if value is not None and context.get(key) not in (None, value):
                    raise ValueError(
                        f"workflow already uses {key}={context.get(key)!r}, "
                        f"not {value!r}"
                    )
            if "authoring" in state:
                state = _recover_yolo_state(root, path, state)
                record, _ = _current_yolo_record(root, path, state)
                inventory_hash = record["inventory"]["sha256"]
                rule_ids = [rule["ruleId"] for rule in record["inventory"]["rules"]]
                budget_campaign_id = (
                    state.get("budget", {}).get("campaignId")
                    or campaign_id
                )
            else:
                inventory_hash, rule_ids = _budget_source_inventory(root, yolo=False)
                budget_campaign_id = (
                    state.get("budget", {}).get("campaignId")
                    or campaign_id
                )
            existing_budget = state.get("budget")
            link_campaign = False
            if existing_budget:
                if explicit_campaign_id and explicit_campaign_id != existing_budget["campaignId"]:
                    raise ValueError(
                        "workflow is already linked to a different campaign; "
                        "campaign binding is immutable"
                    )
                if existing_budget["inventorySha256"] != inventory_hash:
                    raise ValueError(
                        "campaign frozen source inventory changed; preserve the existing run "
                        "and explicitly initialize a separately reviewed campaign"
                    )
                budget_summary(
                    root, existing_budget["campaignId"], expected_inventory=inventory_hash,
                )
            elif budget_campaign_id:
                campaign_exists = validate_campaign_binding(
                    root,
                    budget_campaign_id,
                    inventory_sha256=inventory_hash,
                    rule_ids=rule_ids,
                )
                if campaign_exists and state["runId"] not in budget_summary(
                    root, budget_campaign_id, expected_inventory=inventory_hash,
                )["linkedRunIds"]:
                    raise BudgetReceiptError(
                        "an unbudgeted existing workflow cannot be joined to an active "
                        "campaign; initialize an explicitly linked replacement run"
                    )
                link_campaign = True
            for key, value in requested_context.items():
                if key == "targetContextLocked":
                    if value:
                        context[key] = True
                    continue
                if value is not None and context.get(key) is None:
                    context[key] = value
            _select_workflow_profile(state, workflow_profile)
            if link_campaign:
                create_or_link_campaign(
                    root,
                    budget_campaign_id,
                    inventory_sha256=inventory_hash,
                    run_id=state["runId"],
                    rule_ids=rule_ids,
                    legacy_usage_unknown=True,
                )
                state["budget"] = {
                    "schemaVersion": "1.0.0",
                    "campaignId": budget_campaign_id,
                    "inventorySha256": inventory_hash,
                    "status": "active",
                    "stopReason": None,
                }
            _write_unlocked(path, state)
            if target:
                write_target(root, target)
            return {
                **state,
                "statePath": str(path),
                "resumed": True,
                "next": _next_stage_name(state),
            }

    frozen_inventory = _source_inventory(root) if yolo is True else None
    if frozen_inventory is not None and not campaign_id:
        raise ValueError("new YOLO workflows require an explicit --campaign-id")
    preflight_inventory = _preflight_campaign_binding(
        root,
        campaign_id,
        yolo=yolo is True,
        inventory=frozen_inventory,
    )
    if yolo is True and requested_run_id(root) is None:
        run = create_run(root)
        with using_run(root, run.name):
            return initialize_workflow(
                root,
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                workspace_resource_id=workspace_resource_id,
                workspace_customer_id=workspace_customer_id,
                version_bump=version_bump,
                workflow_profile=workflow_profile,
                yolo=True,
                campaign_id=campaign_id,
            )

    now = _utc_now()
    path = artifact_path(root, STATE_FILE_NAME, create_parent=True)
    state = {
        "schemaVersion": SCHEMA_VERSION,
        "solution": str(root),
        "workflowStatus": "inProgress",
        "createdAt": now,
        "updatedAt": now,
        "context": requested_context,
        "stages": {
            name: _stage_result(
                name,
                required=not (
                    workflow_profile == "authoring"
                    and name in AUTHORING_OPTIONAL_STAGES
                ),
            )
            for name in STAGES
        },
    }
    state["context"]["workflowProfile"] = workflow_profile
    state["context"]["profileSelectionConfirmed"] = True
    if frozen_inventory is not None:
        record, _ = _persist_contract_snapshot(
            path.parent,
            state,
            _contract_core(
                root,
                path.parent.name,
                frozen_inventory,
                revision=1,
                previous_sha256=None,
            ),
        )
        campaign_inventory_hash = record["inventory"]["sha256"]
        campaign_rule_ids = [rule["ruleId"] for rule in record["inventory"]["rules"]]
    else:
        campaign_inventory_hash, campaign_rule_ids = (
            preflight_inventory
            if preflight_inventory is not None
            else _budget_source_inventory(root, yolo=False)
        )
    if campaign_id:
        create_or_link_campaign(
            root,
            campaign_id,
            inventory_sha256=campaign_inventory_hash,
            run_id=path.parent.name,
            rule_ids=campaign_rule_ids,
        )
        state["budget"] = {
            "schemaVersion": "1.0.0",
            "campaignId": campaign_id,
            "inventorySha256": campaign_inventory_hash,
            "status": "active",
            "stopReason": None,
        }
    _write(path, state)
    if target:
        write_target(root, target)
    return {
        **state,
        "statePath": str(path),
        "resumed": False,
        "next": _next_stage_name(state),
    }


def _select_workflow_profile(state: dict[str, Any], workflow_profile: str) -> None:
    context = state["context"]
    current = context["workflowProfile"]
    if current != workflow_profile:
        protected = [
            name
            for name in (*AUTHORING_OPTIONAL_STAGES, "report")
            if state["stages"][name]["status"] not in {"pending", "notRequired"}
        ]
        if protected:
            raise ValueError(
                "workflow profile cannot change after qualification/report stages "
                f"started: {', '.join(sorted(protected))}"
            )
        for name in AUTHORING_OPTIONAL_STAGES:
            state["stages"][name] = _stage_result(
                name,
                required=workflow_profile == "qualification",
            )
        context["workflowProfile"] = workflow_profile
    context["profileSelectionConfirmed"] = True


def _validate_packaging_evidence(
    state: dict[str, Any],
    artifacts: dict[str, str],
    solution: str | Path,
) -> None:
    if artifacts.get("packager") != "V3.1":
        raise ValueError("passed packaging stage requires packager=V3.1; rebuild old packages")
    report_value = artifacts.get("packageReport")
    if not report_value:
        raise ValueError("passed packaging stage requires a V3.1 packageReport artifact")
    report_path = resolve_artifact_reference(solution, report_value)
    if not report_path.is_file():
        raise ValueError(f"V3.1 package report does not exist: {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"V3.1 package report is invalid: {report_path}: {exc}") from exc
    if not isinstance(report, dict) or report.get("packager") != "V3.1":
        raise ValueError(f"package report does not prove V3.1 packaging: {report_path}")
    selection = verify_applied_package_selection(solution, str(state.get("runId") or ""))
    validation_status = state["stages"]["validation"]["status"]
    if validation_status != "passed":
        if not selection:
            raise ValueError(
                "partial V3.1 packaging requires a fresh, applied evidence-based selection plan"
            )
        plan = selection["plan"]
        verification = report.get("selectionVerification") or {}
        summary = plan.get("summary") or {}
        if (
            plan.get("summary", {}).get("outcome") != "partial"
            or not _partial_coverage_allowed(summary)
            or report.get("selectionOutcome") != "partial-package-validated"
            or report.get("selectionPlanSha256") != plan.get("planSha256")
            or artifacts.get("selectionPlanSha256") != plan.get("planSha256")
            or report.get("selectionSummary") != summary
            or verification.get("planSha256") != plan.get("planSha256")
            or verification.get("outcome") != "partial"
            or verification.get("analyticRuleIncluded")
            != summary.get("analyticRuleIncluded")
            or verification.get("xdrDetectionIncluded")
            != summary.get("xdrDetectionIncluded")
            or verification.get("coverageNumerator")
            != summary.get("coverageNumerator")
            or verification.get("coverageDenominator")
            != summary.get("coverageDenominator")
            or verification.get("partialPublicationAllowed") is not True
            or verification.get("mainTemplateVerified") is not True
            or verification.get("zipVerified") is not True
        ):
            raise ValueError(
                "partial package evidence does not bind the complete current excluded inventory"
            )
    elif selection:
        plan = selection["plan"]
        summary = plan.get("summary") or {}
        verification = report.get("selectionVerification") or {}
        if (
            report.get("selectionPlanSha256") != plan.get("planSha256")
            or artifacts.get("selectionPlanSha256") != plan.get("planSha256")
            or report.get("selectionSummary") != summary
            or verification.get("planSha256") != plan.get("planSha256")
            or verification.get("analyticRuleIncluded")
            != summary.get("analyticRuleIncluded")
            or verification.get("xdrDetectionIncluded")
            != summary.get("xdrDetectionIncluded")
            or verification.get("mainTemplateVerified") is not True
            or verification.get("zipVerified") is not True
        ):
            raise ValueError("V3.1 package report does not match the applied selection plan")
    for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip"):
        value = artifacts.get(name) or report.get(name)
        if not value or not resolve_artifact_reference(solution, value).is_file():
            raise ValueError(f"V3.1 packaging evidence is missing artifact: {name}")
    packaging = state.get("packaging")
    requested_bump = state["context"].get("versionBump")
    effective_bump = (
        ((packaging.get("currentAttempt") or {}).get("effectiveVersionBump"))
        if packaging else requested_bump
    )
    if effective_bump is not None and report.get("versionBump") != effective_bump:
        raise ValueError(
            "V3.1 package report version bump does not match workflow context: "
            f"{report.get('versionBump')!r} != {effective_bump!r}"
        )
    if packaging:
        attempt = packaging.get("currentAttempt") or {}
        if (
            attempt.get("status") != "passed"
            or report.get("packageAttemptId") != attempt.get("attemptId")
            or report.get("workflowRunId") != state.get("runId")
            or report.get("requestedVersionBump") != attempt.get("requestedVersionBump")
            or report.get("effectiveVersionBump") != attempt.get("effectiveVersionBump")
        ):
            raise ValueError("V3.1 package report is stale or belongs to another workflow attempt")
        input_after = (report.get("packageInputs") or {}).get("after") or {}
        if input_after.get("sha256") != attempt.get("packageInputSha256"):
            raise ValueError("V3.1 package input identity does not match the current workflow attempt")
        recorded_hashes = report.get("packageArtifactHashes")
        if not isinstance(recorded_hashes, dict):
            raise ValueError("V3.1 package report has no package artifact hashes")
        for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip"):
            path = resolve_artifact_reference(solution, artifacts.get(name) or report.get(name))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if recorded_hashes.get(name) != digest:
                raise ValueError(f"V3.1 package artifact is stale: {name}")
        report_digest = hashlib.sha256(report_path.read_bytes()).hexdigest()
        if report_digest != attempt.get("packageReportSha256"):
            raise ValueError("V3.1 package report hash does not match the current workflow attempt")


def _yolo_package_readiness(
    solution: Path,
    state_path: Path,
    state: dict[str, Any],
    *,
    allow_partial_selection: bool = False,
) -> None:
    """Require the full YOLO inventory to clear technical and explicit-review gates."""
    validation_status = state["stages"]["validation"]["status"]
    if validation_status != "passed" and not (
        allow_partial_selection
        and not state.get("authoring")
        and validation_status == "blocked"
    ):
        raise ValueError("YOLO packaging requires the existing validation stage to pass")
    if allow_partial_selection and not state.get("authoring"):
        return
    if not state.get("authoring"):
        output = Path(solution).expanduser().resolve() / "XDR Detections"
        pending: list[str] = []
        for path in xdr_detection_files(output):
            try:
                document = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
            except (OSError, UnicodeError, yaml.YAMLError) as exc:
                raise ValueError(f"cannot verify XDR review state in {path}: {exc}") from exc
            if not isinstance(document, dict):
                raise ValueError(f"cannot verify XDR review state in {path}: document is not an object")
            conversion = ((document.get("contentProvenance") or {}).get("conversion") or {})
            if (
                isinstance(conversion, dict)
                and (
                    conversion.get("reviewRequired") is True
                    or conversion.get("status") == "needsReview"
                )
            ):
                pending.append(path.relative_to(solution).as_posix())
        if pending:
            raise ValueError(
                "V3.1 packaging is blocked by unresolved detection review flags: "
                + ", ".join(sorted(pending))
            )
        return
    record, _ = _current_yolo_record(solution, state_path, state)
    results = record.get("results") or []
    rules = record.get("inventory", {}).get("rules") or []
    if len(results) != len(rules) or not results:
        raise ValueError("YOLO packaging requires complete full-inventory authoring results")
    blockers = []
    for result in results:
        rule_id = result.get("ruleId", "<unknown>")
        if (
            result.get("status") != "migrated"
            or result.get("conversionStatus") != "converted"
            or result.get("validationStatus") != "passed"
            or result.get("reviewRequired") is True
            or (result.get("target") or {}).get("structurallyValid") is not True
            or any(
                finding.get("kind") == "error" and finding.get("unresolved") is True
                for finding in result.get("findings", [])
            )
        ):
            blockers.append(rule_id)
    if blockers:
        raise ValueError(
            "YOLO packaging is blocked by unresolved technical or explicit-review "
            "items in the complete inventory: " + ", ".join(blockers)
        )


def _verify_current_package_state(solution: Path, state: dict[str, Any]) -> None:
    packaging = state.get("packaging") or {}
    successful = packaging.get("lastSuccessful") or {}
    if not successful.get("packageSucceeded"):
        raise ValueError("workflow has no successful current V3.1 package attempt")
    if package_input_identity(solution)["sha256"] != successful.get("packageInputSha256"):
        raise ValueError("package inputs changed after V3.1 packaging; rebuild before continuing")
    report_reference = successful.get("packageReport")
    if not isinstance(report_reference, str) or not report_reference:
        raise ValueError("current V3.1 package report reference is missing")
    report_path = resolve_artifact_reference(solution, report_reference)
    if not report_path.is_file():
        raise ValueError("current V3.1 package report is missing")
    report_bytes = report_path.read_bytes()
    if hashlib.sha256(report_bytes).hexdigest() != successful.get("packageReportSha256"):
        raise ValueError("current V3.1 package report is stale or modified")
    report = json.loads(report_bytes)
    if (
        report.get("packager") != "V3.1"
        or report.get("workflowRunId") != state.get("runId")
        or report.get("packageAttemptId") != successful.get("attemptId")
        or report.get("packageArtifactsSha256") != successful.get("packageArtifactsSha256")
    ):
        raise ValueError("current package report does not match the successful V3.1 workflow attempt")
    if report.get("selectionPlanSha256") is not None:
        selection = verify_applied_package_selection(
            solution, str(state.get("runId") or ""),
        )
        if (
            not selection
            or selection["plan"].get("planSha256") != report.get("selectionPlanSha256")
        ):
            raise ValueError("current V3.1 package selection evidence is stale or mismatched")
        summary = selection["plan"].get("summary") or {}
        if (
            summary.get("outcome") == "partial"
            and (
                not _partial_coverage_allowed(summary)
                or report.get("selectionOutcome") != "partial-package-validated"
            )
        ):
            raise ValueError("current partial package no longer meets migrated-detection coverage")
    elif report.get("selectionOutcome") == "partial-package-validated":
        raise ValueError("partial V3.1 package is missing its selection-plan binding")
    recorded_hashes = report.get("packageArtifactHashes") or {}
    for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip"):
        artifact = report.get(name)
        if not artifact:
            raise ValueError(f"current V3.1 package report has no {name} artifact")
        path = resolve_artifact_reference(solution, artifact)
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != recorded_hashes.get(name)
        ):
            raise ValueError(f"current V3.1 package artifact is stale: {name}")


def _package_freshness(solution: str | Path, state: dict[str, Any]) -> dict[str, Any] | None:
    successful = (state.get("packaging") or {}).get("lastSuccessful")
    if not successful:
        return None
    try:
        current_identity = package_input_identity(solution)["sha256"]
    except (OSError, ValueError) as exc:
        return {
            "status": "unverifiable",
            "currentPackageInputSha256": None,
            "packagedInputSha256": successful.get("packageInputSha256"),
            "reason": str(exc),
        }
    packaged_identity = successful.get("packageInputSha256")
    if current_identity != packaged_identity:
        return {
            "status": "stale",
            "currentPackageInputSha256": current_identity,
            "packagedInputSha256": packaged_identity,
            "reason": "solution package inputs changed after the successful V3.1 build",
        }
    try:
        _verify_current_package_state(Path(solution).expanduser().resolve(), state)
    except (OSError, ValueError, json.JSONDecodeError, TypeError, AttributeError) as exc:
        return {
            "status": "stale",
            "currentPackageInputSha256": current_identity,
            "packagedInputSha256": packaged_identity,
            "reason": str(exc),
        }
    return {
        "status": "current",
        "currentPackageInputSha256": current_identity,
        "packagedInputSha256": packaged_identity,
        "reason": None,
    }


def _archive_package_evidence(
    solution: Path,
    successful: dict[str, Any],
) -> dict[str, str]:
    report_reference = successful.get("packageReport")
    if not isinstance(report_reference, str) or not report_reference:
        raise ValueError("prior V3.1 package report reference is missing")
    report_path = resolve_artifact_reference(solution, report_reference)
    if not report_path.is_file():
        raise ValueError("prior V3.1 package report is missing")
    report_bytes = report_path.read_bytes()
    if hashlib.sha256(report_bytes).hexdigest() != successful.get("packageReportSha256"):
        raise ValueError("prior V3.1 package report is stale or modified")
    report = json.loads(report_bytes)
    if report.get("packager") != "V3.1":
        raise ValueError("prior package evidence is not from V3.1")
    attempt_id = str(successful.get("attemptId") or uuid.uuid4())
    archive = report_path.parent / "package-history" / attempt_id
    files = {"packageReport": report_path}
    files.update({
        name: resolve_artifact_reference(solution, report[name])
        for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip")
        if isinstance(report.get(name), str) and report[name]
    })
    if set(files) != {
        "packageReport", "mainTemplate", "createUiDefinition", "testParameters", "zip",
    }:
        raise ValueError("prior V3.1 package report is missing artifact references")
    recorded_hashes = report.get("packageArtifactHashes") or {}
    archived: dict[str, str] = {}
    for name, source in files.items():
        if not source.is_file():
            raise ValueError(f"prior V3.1 package artifact is missing: {name}")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        expected = (
            successful.get("packageReportSha256")
            if name == "packageReport" else recorded_hashes.get(name)
        )
        if digest != expected:
            raise ValueError(f"prior V3.1 package artifact is stale: {name}")
    archive.mkdir(parents=True, exist_ok=False)
    for name, source in files.items():
        destination = archive / f"{name}-{source.name}"
        shutil.copy2(source, destination)
        archived[name] = destination.relative_to(solution).as_posix()
    return archived


def plan_new_package_release(
    solution: str | Path,
    *,
    version_bump: str,
    expected_package_input_sha256: str,
) -> dict[str, Any]:
    """Explicitly reopen a stale package stage for one versioned V3.1 release action."""
    if version_bump not in {"patch", "minor", "major"}:
        raise ValueError("new package release action must be patch, minor, or major")
    if not re.fullmatch(r"[a-f0-9]{64}", expected_package_input_sha256 or ""):
        raise ValueError("expected package input identity must be a lowercase SHA-256")

    root = Path(solution).expanduser().resolve()
    with _state_writer_lock(root) as path:
        loaded_path, state = _load(root)
        if loaded_path != path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        if state.get("context", {}).get("profileSelectionConfirmed") is not True:
            raise ValueError("release planning requires explicit profile selection")
        if state.get("authoring") and state["authoring"]["status"] != "active":
            raise ValueError("stopped or conflicted YOLO runs cannot plan a package release")
        selection_evidence = verify_applied_package_selection(
            root, str(state["runId"]),
        )
        partial_selection = bool(
            selection_evidence
            and selection_evidence["plan"].get("summary", {}).get("outcome") == "partial"
        )
        validation_status = state["stages"]["validation"]["status"]
        partial_release_ready = (
            partial_selection
            and validation_status == "blocked"
            and not state.get("authoring")
            and state["stages"]["conversion"]["status"] == "passed"
        )
        complete_selection = bool(
            selection_evidence
            and selection_evidence["plan"].get("summary", {}).get("outcome") == "complete"
        )
        complete_release_ready = (
            complete_selection
            and validation_status == "passed"
            and state["stages"]["conversion"]["status"] == "passed"
        )
        first_release_ready = partial_release_ready or complete_release_ready
        _yolo_package_readiness(
            root,
            path,
            state,
            allow_partial_selection=partial_release_ready,
        )
        if any(
            state["stages"][dependency]["status"] != "passed"
            for dependency in _dependencies(state, "packaging")
            if not (dependency == "validation" and partial_release_ready)
        ):
            raise ValueError("package release planning is blocked by unfinished prerequisites")
        if not first_release_ready and validation_status != "passed":
            raise ValueError(
                "package release planning requires passed validation or a fresh, "
                "applied partial package selection with all exclusions accounted for"
            )

        current_identity = package_input_identity(root)["sha256"]
        if current_identity != expected_package_input_sha256:
            raise ValueError(
                "package inputs changed after release action selection; refresh status "
                "and explicitly select an action for the current input identity"
            )

        package_state = state.get("packaging")
        if not isinstance(package_state, dict):
            package_state = {
                "schemaVersion": "1.0.0",
                "lastSuccessful": None,
                "lastConsumedAction": None,
                "currentAttempt": None,
                "releaseActions": [],
                "pendingReleaseAction": None,
            }
            state["packaging"] = package_state
        package_state.setdefault("releaseActions", [])
        package_state.setdefault("pendingReleaseAction", None)
        if (package_state.get("currentAttempt") or {}).get("status") == "running":
            raise ValueError("cannot plan a new release while V3.1 packaging is running")
        prior = package_state.get("lastSuccessful")
        last_consumed = package_state.get("lastConsumedAction") or {}
        if prior is None and last_consumed.get("bumpConsumed") is True:
            if last_consumed.get("packageInputSha256") == current_identity:
                raise ValueError(
                    "the initial version action was consumed by a failed build; retry "
                    "with --version-bump none for the matching package inputs"
                )
            raise ValueError(
                "package inputs changed after the initial version action was consumed; "
                "the failed build's retry rules must be resolved before planning a new release"
            )
        if prior is None and not first_release_ready:
            raise ValueError(
                "first release planning without a prior successful V3.1 package requires "
                "a fresh applied complete selection with passed validation, or an eligible "
                "partial selection with blocked validation"
            )
        if prior and current_identity == prior.get("packageInputSha256"):
            raise ValueError(
                "package inputs still match the successful V3.1 package; "
                "a new release action is not warranted"
            )
        pending = package_state.get("pendingReleaseAction")
        if pending:
            if pending.get("packageInputSha256") == current_identity:
                raise ValueError(
                    "a release action is already selected for these package inputs; "
                    "continue package-v3-1 with that exact action"
                )
            raise ValueError(
                "package inputs changed after the pending release action was selected"
            )
        if any(
            item.get("packageInputSha256") == current_identity
            and item.get("versionBump") == version_bump
            for item in package_state["releaseActions"]
        ):
            raise ValueError("this explicit release action was already consumed for these inputs")

        selected_at = _utc_now()
        historical_evidence = (
            _archive_package_evidence(root, prior) if prior else {}
        )
        package_state["releaseActions"].append({
            "versionBump": version_bump,
            "packageInputSha256": current_identity,
            "selectedAt": selected_at,
            "status": "selected",
            "historicalEvidence": historical_evidence,
        })
        package_state["pendingReleaseAction"] = {
            "versionBump": version_bump,
            "packageInputSha256": current_identity,
            "selectedAt": selected_at,
        }
        for name in ("packaging", "deployment", "mockIngestion", "alertParity", "report"):
            stage = state["stages"][name]
            if stage["status"] != "notRequired":
                stage.update({
                    "status": "blocked",
                    "completedAt": None,
                    "message": (
                        "Package inputs changed after the prior V3.1 release. "
                        "Prior artifacts and evidence are historical; an explicit "
                        "new release action was selected."
                    ),
                })
        state["workflowStatus"] = "blocked"
        _write_unlocked(path, state)
        return {
            "runId": state["runId"],
            "versionBump": version_bump,
            "packageInputSha256": current_identity,
            "selectedAt": selected_at,
            "next": _next_stage_name(state),
            "workflowStatus": state["workflowStatus"],
        }


def package_workflow_v3_1(
    solution: str | Path,
    *,
    requested_version_bump: str,
    toolkit_root: str | Path | None = None,
) -> dict[str, Any]:
    """Package one current workflow attempt and persist fresh, hash-bound evidence."""
    if requested_version_bump not in {"none", "patch", "minor", "major"}:
        raise ValueError("version bump must be none, patch, minor, or major")
    root = Path(solution).expanduser().resolve()
    with _state_writer_lock(root) as path:
        loaded_path, state = _load(root)
        if loaded_path != path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        if not state.get("runId"):
            raise ValueError("workflow packaging requires an explicitly selected run")
        if state["context"].get("profileSelectionConfirmed") is not True:
            raise ValueError("workflow packaging requires explicit profile selection")
        selection_evidence = verify_applied_package_selection(
            root, str(state["runId"]),
        )
        validation_status = state["stages"]["validation"]["status"]
        partial_selection = bool(
            selection_evidence
            and selection_evidence["plan"].get("summary", {}).get("outcome") == "partial"
        )
        if validation_status != "passed" and not (
            partial_selection
            and validation_status == "blocked"
            and not state.get("authoring")
        ):
            raise ValueError(
                "workflow packaging requires passed validation or a fresh, applied "
                "partial package selection with all exclusions accounted for"
            )
        _yolo_package_readiness(
            root,
            path,
            state,
            allow_partial_selection=partial_selection,
        )
        if state.get("authoring") and state["authoring"]["status"] != "active":
            raise ValueError("stopped or conflicted YOLO runs cannot be packaged")
        campaign_budget = state.get("budget")
        if not campaign_budget and state.get("authoring"):
            raise ValueError(
                "YOLO V3.1 package builds require a persisted campaign budget; resume "
                "workflow-init with its explicit --campaign-id to link this run conservatively"
            )
        if campaign_budget and campaign_budget.get("status") == "stopped":
            raise ValueError(
                "budget-stopped workflow runs cannot be resumed by an extension; "
                "initialize an explicitly linked replacement run"
            )
        if campaign_budget:
            current_inventory_hash, _ = _budget_source_inventory(
                root,
                yolo=bool(state.get("authoring")),
            )
            if current_inventory_hash != campaign_budget["inventorySha256"]:
                raise ValueError(
                    "campaign frozen source inventory changed; package inputs are no longer "
                    "bound to this campaign"
                )
            budget_summary(
                root,
                campaign_budget["campaignId"],
                expected_inventory=current_inventory_hash,
            )
        pending_dependencies = [
            dependency
            for dependency in _dependencies(state, "packaging")
            if state["stages"][dependency]["status"] != "passed"
        ]
        if pending_dependencies and not (
            pending_dependencies == ["validation"]
            and partial_selection
            and validation_status == "blocked"
            and not state.get("authoring")
        ):
            raise ValueError("workflow packaging is blocked by unfinished prerequisites")

        inputs = package_input_identity(root)
        if campaign_budget:
            prior_package_attempts = package_history(
                root, campaign_budget["campaignId"],
            )
            last_consumed = next((
                item for item in reversed(prior_package_attempts)
                if item["finish"]
                and (item["finish"].get("completionMetadata") or {}).get("bumpConsumed") is True
            ), None)
            if last_consumed:
                prior_after = (
                    last_consumed["finish"].get("completionMetadata") or {}
                ).get("packageInputSha256After")
                if prior_after == inputs["sha256"] and requested_version_bump != "none":
                    raise ValueError(
                        "a campaign version action was already consumed for unchanged "
                        "package inputs; use --version-bump none"
                    )
                if prior_after != inputs["sha256"] and requested_version_bump == "none":
                    raise ValueError(
                        "campaign package inputs changed after the consumed version action; "
                        "select an explicit new version bump"
                    )
        package_state = state.get("packaging") or {
            "schemaVersion": "1.0.0",
            "lastSuccessful": None,
            "lastConsumedAction": None,
            "currentAttempt": None,
            "releaseActions": [],
            "pendingReleaseAction": None,
        }
        package_state.setdefault("releaseActions", [])
        package_state.setdefault("pendingReleaseAction", None)
        previous = package_state.get("lastSuccessful")
        previous_successful = previous
        last_consumed = package_state.get("lastConsumedAction") or {}
        pending_release = package_state.get("pendingReleaseAction")
        failed_consumed_retry = (
            last_consumed.get("bumpConsumed") is True
            and last_consumed.get("packageSucceeded") is False
            and last_consumed.get("packageInputSha256") == inputs["sha256"]
        )
        if previous is not None and inputs["sha256"] != previous.get("packageInputSha256"):
            if not pending_release and not failed_consumed_retry:
                raise ValueError(
                    "package inputs changed after V3.1 packaging; select an explicit "
                    "new release action before rebuilding"
                )
            if pending_release and (
                pending_release.get("packageInputSha256") != inputs["sha256"]
                or pending_release.get("versionBump") != requested_version_bump
            ):
                raise ValueError(
                    "package input identity or version action differs from the explicitly "
                    "selected new release action"
                )
        elif pending_release and (
            pending_release.get("packageInputSha256") != inputs["sha256"]
            or pending_release.get("versionBump") != requested_version_bump
        ):
            raise ValueError(
                "pending release action no longer matches changed package inputs"
            )
        if (
            previous is not None
            and inputs["sha256"] == previous.get("packageInputSha256")
            and requested_version_bump != "none"
        ):
            raise ValueError(
                "a V3.1 package already exists for unchanged inputs; use "
                "--version-bump none for a repeat build"
            )
        if failed_consumed_retry and requested_version_bump != "none":
            raise ValueError(
                "the selected release action was consumed by a failed build; retry "
                "with --version-bump none for the matching package inputs"
            )
        if (
            requested_version_bump == "none"
            and last_consumed.get("bumpConsumed") is True
        ):
            if inputs["sha256"] != last_consumed.get("packageInputSha256"):
                raise ValueError(
                    "package inputs changed after the consumed version action; "
                    "select an explicit new version bump"
                )
            effective_bump = "none"
        elif pending_release:
            effective_bump = pending_release["versionBump"]
        elif previous is None:
            selected_bump = state["context"].get("versionBump")
            if selected_bump is not None and selected_bump != requested_version_bump:
                raise ValueError(
                    "requested package version bump differs from the workflow's "
                    f"selected action: {requested_version_bump!r} != {selected_bump!r}"
                )
            if selected_bump is None:
                state["context"]["versionBump"] = requested_version_bump
            effective_bump = requested_version_bump
        elif requested_version_bump == "none":
            raise ValueError(
                "retry with version bump none is allowed only after the original "
                "version action was consumed"
            )
        else:
            effective_bump = requested_version_bump

        stage = state["stages"]["packaging"]
        if stage["status"] == "notRequired":
            raise ValueError("packaging is not required for this workflow")
        attempt_number = stage["attempts"] + 1
        attempt_id = str(uuid.uuid4())
        started_at = _utc_now()
        stage.update({
            "status": "running",
            "attempts": attempt_number,
            "startedAt": started_at,
            "completedAt": None,
            "message": None,
            "artifacts": {},
            "evidence": [],
        })
        package_state["currentAttempt"] = {
            "attemptId": attempt_id,
            "attempt": attempt_number,
            "status": "running",
            "requestedVersionBump": requested_version_bump,
            "effectiveVersionBump": effective_bump,
            "bumpConsumed": False,
            "packageInputSha256": inputs["sha256"],
            "packageReportSha256": None,
            "startedAt": started_at,
        }
        state["packaging"] = package_state
        state["workflowStatus"] = "inProgress"
        _write_unlocked(path, state)

        version_before = solution_data_version(root)
        try:
            if campaign_budget:
                package_receipt_details: dict[str, Any] = {}
                operation = measured_operation(
                    root,
                    campaign_budget["campaignId"],
                    inventory_sha256=campaign_budget["inventorySha256"],
                    run_id=state["runId"],
                    dimension="packageBuild",
                    metadata={
                        "packageInputSha256": inputs["sha256"],
                        "requestedVersionBump": requested_version_bump,
                        "effectiveVersionBump": effective_bump,
                    },
                    completion_metadata=package_receipt_details,
                )
            else:
                from contextlib import nullcontext
                operation = nullcontext()
                package_receipt_details = {}
            package_dispatched = False
            with operation:
                try:
                    current_selection = verify_applied_package_selection(
                        root, str(state["runId"]),
                    )
                    if (
                        selection_evidence
                        and (
                            not current_selection
                            or current_selection["plan"].get("planSha256")
                            != selection_evidence["plan"].get("planSha256")
                        )
                    ):
                        raise ValueError(
                            "applied package selection changed after the workflow attempt was authorized"
                        )
                    package_dispatched = True
                    result = package_solution_v3_1(
                        root,
                        version_bump=effective_bump,
                        toolkit_root=toolkit_root,
                        requested_version_bump=requested_version_bump,
                        package_attempt_id=attempt_id,
                        workflow_run_id=state["runId"],
                        selection_plan=(
                            current_selection["plan"] if current_selection else None
                        ),
                    )
                except BaseException:
                    version_after_failure = solution_data_version(root)
                    consumed_on_failure = version_bump_was_consumed(
                        version_before, version_after_failure, effective_bump,
                    )
                    package_receipt_details.update({
                        "bumpConsumed": consumed_on_failure,
                        "packageInputSha256After": (
                            package_input_identity(root)["sha256"]
                            if consumed_on_failure else inputs["sha256"]
                        ),
                    })
                    raise
                else:
                    package_receipt_details.update({
                        "bumpConsumed": version_bump_was_consumed(
                            version_before, solution_data_version(root), effective_bump,
                        ),
                        "packageInputSha256After": package_input_identity(root)["sha256"],
                    })
                    report_for_receipt = json.loads(
                        Path(result["packageReport"]).read_text(encoding="utf-8-sig")
                    )
                    receipt_inputs = report_for_receipt.get("packageInputs") or {}
                    report_after = (receipt_inputs.get("after") or {}).get("sha256")
                    if report_after:
                        package_receipt_details["packageInputSha256After"] = report_after
            report_path = resolve_artifact_reference(root, result["packageReport"])
            report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            report_inputs = report.get("packageInputs") or {}
            report_before = (report_inputs.get("before") or {}).get("sha256")
            if report_before != inputs["sha256"]:
                raise ValueError("package inputs changed after the workflow attempt was authorized")
            input_after = (report_inputs.get("after") or {}).get("sha256")
            if not input_after:
                raise ValueError("V3.1 package report has no post-build package input identity")
            current_attempt = package_state["currentAttempt"]
            current_attempt.update({
                "status": "passed",
                "bumpConsumed": True,
                "packageInputSha256": input_after,
                "packageReportSha256": report_hash,
                "completedAt": _utc_now(),
            })
            package_state["lastConsumedAction"] = {
                "requestedVersionBump": requested_version_bump,
                "effectiveVersionBump": effective_bump,
                "bumpConsumed": True,
                "packageInputSha256": input_after,
                "attemptId": attempt_id,
                "packageSucceeded": True,
            }
            if pending_release:
                for release_action in reversed(package_state["releaseActions"]):
                    if (
                        release_action["status"] == "selected"
                        and release_action["packageInputSha256"] == inputs["sha256"]
                    ):
                        release_action["status"] = "consumed"
                        break
                package_state["pendingReleaseAction"] = None
            artifacts = dict(result["workflowArtifacts"])
            artifacts.update({
                "requestedVersionBump": requested_version_bump,
                "effectiveVersionBump": effective_bump,
                "packageAttemptId": attempt_id,
                "packageInputSha256": input_after,
                "packageReportSha256": report_hash,
            })
            if selection_evidence:
                artifacts.update({
                    "selectionPlan": selection_evidence["planPath"],
                    "selectionReceipt": selection_evidence["receiptPath"],
                    "selectionPlanSha256": selection_evidence["plan"]["planSha256"],
                    "selectionOutcome": report.get("selectionOutcome"),
                })
            stage.update({
                "status": "passed",
                "completedAt": _utc_now(),
                "message": (
                    "Fresh V3.1 package evidence verified for the current workflow attempt."
                    if validation_status == "passed"
                    else "Fresh partial V3.1 package evidence verified; excluded inventory remains unchanged."
                ),
                "artifacts": artifacts,
                "evidence": [result["packageReport"]],
            })
            _validate_packaging_evidence(state, artifacts, root)
            package_state["lastSuccessful"] = {
                **package_state["lastConsumedAction"],
                "packageReport": result["packageReport"],
                "packageReportSha256": report_hash,
                "packageArtifactsSha256": report.get("packageArtifactsSha256"),
                "version": result["version"],
            }
            state["workflowStatus"] = (
                "inProgress"
            )
            _write_unlocked(path, state)
            return {
                **result,
                "runId": state["runId"],
                "workflowStatus": state["workflowStatus"],
                "next": _next_stage_name(state),
            }
        except BudgetError as exc:
            if package_dispatched:
                package_state["lastSuccessful"] = previous_successful
                current_attempt = package_state["currentAttempt"]
                version_after = solution_data_version(root)
                consumed = version_bump_was_consumed(
                    version_before, version_after, effective_bump
                )
                if consumed:
                    try:
                        input_after_failure = package_input_identity(root)["sha256"]
                    except (OSError, ValueError):
                        input_after_failure = None
                    if input_after_failure:
                        package_state["lastConsumedAction"] = {
                            "requestedVersionBump": requested_version_bump,
                            "effectiveVersionBump": effective_bump,
                            "bumpConsumed": True,
                            "packageInputSha256": input_after_failure,
                            "attemptId": attempt_id,
                            "packageSucceeded": False,
                        }
                        current_attempt["bumpConsumed"] = True
                        current_attempt["packageInputSha256"] = input_after_failure
                        if pending_release:
                            package_state["pendingReleaseAction"] = None
                            for release_action in reversed(package_state["releaseActions"]):
                                if (
                                    release_action["status"] == "selected"
                                    and release_action["packageInputSha256"] == inputs["sha256"]
                                ):
                                    release_action["status"] = "consumed"
                                    break
                current_attempt.update({
                    "status": "failed",
                    "completedAt": _utc_now(),
                    "failure": f"V3.1 build was dispatched but receipt persistence failed: {exc}"[:1000],
                })
                stage.update({
                    "status": "failed",
                    "completedAt": _utc_now(),
                    "message": f"V3.1 build was dispatched but receipt persistence failed: {exc}"[:2000],
                    "artifacts": {},
                    "evidence": [],
                })
                state["workflowStatus"] = "failed"
                _write_unlocked(path, state)
                raise
            package_state["lastSuccessful"] = previous_successful
            current_attempt = package_state["currentAttempt"]
            current_attempt.update({
                "status": "blocked",
                "completedAt": _utc_now(),
                "failure": str(exc)[:1000],
            })
            stage.update({
                "status": "blocked",
                "completedAt": _utc_now(),
                "message": f"V3.1 build was not dispatched: {exc}"[:2000],
                "artifacts": {},
                "evidence": [],
            })
            _stop_budget_run(path, state, "packaging", str(exc))
            raise
        except Exception as exc:
            package_state["lastSuccessful"] = previous_successful
            current_attempt = package_state["currentAttempt"]
            version_after = solution_data_version(root)
            consumed = version_bump_was_consumed(
                version_before, version_after, effective_bump
            )
            if consumed:
                try:
                    input_after_failure = package_input_identity(root)["sha256"]
                except (OSError, ValueError):
                    input_after_failure = None
                if input_after_failure:
                    package_state["lastConsumedAction"] = {
                        "requestedVersionBump": requested_version_bump,
                        "effectiveVersionBump": effective_bump,
                        "bumpConsumed": True,
                        "packageInputSha256": input_after_failure,
                        "attemptId": attempt_id,
                        "packageSucceeded": False,
                    }
                    current_attempt["bumpConsumed"] = True
                    current_attempt["packageInputSha256"] = input_after_failure
                    if pending_release:
                        package_state["pendingReleaseAction"] = None
                        for release_action in reversed(package_state["releaseActions"]):
                            if (
                                release_action["status"] == "selected"
                                and release_action["packageInputSha256"] == inputs["sha256"]
                            ):
                                release_action["status"] = "consumed"
                                break
            current_attempt.update({
                "status": "failed",
                "completedAt": _utc_now(),
                "failure": str(exc)[:1000],
            })
            stage.update({
                "status": "failed",
                "completedAt": _utc_now(),
                "message": f"V3.1 package attempt failed: {exc}"[:2000],
                "artifacts": {},
                "evidence": [],
            })
            state["workflowStatus"] = "failed"
            _write_unlocked(path, state)
            raise


def workflow_status(solution: str | Path) -> dict[str, Any]:
    path, state = _load(solution)
    from .runtime import current_runtime_evidence

    try:
        runtime_evidence = current_runtime_evidence(solution)
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        runtime_evidence = {
            "passed": False,
            "sourceStatus": "blocked",
            "sourceWhitelist": [],
            "issues": [f"current runtime assessment unavailable: {type(exc).__name__}"],
        }
    authoring_summary = None
    if state.get("authoring"):
        document, _ = _load_contract_snapshot(path.parent, state["authoring"]["currentContract"])
        authoring_summary = {
            "status": state["authoring"]["status"],
            "contract": state["authoring"]["currentContract"],
            "coverage": document["coverage"],
            "inventorySha256": document["inventory"]["sha256"],
        }
    freshness = _package_freshness(solution, state)
    next_stage = _next_stage_name(state)
    if freshness and freshness["status"] != "current":
        next_stage = "packaging"
    partial_package_summary = None
    packaging_stage = (state.get("stages") or {}).get("packaging") or {}
    packaging_artifacts = packaging_stage.get("artifacts") or {}
    if (
        packaging_stage.get("status") == "passed"
        and packaging_artifacts.get("selectionOutcome") == "partial-package-validated"
        and freshness
        and freshness.get("status") == "current"
    ):
        successful = ((state.get("packaging") or {}).get("lastSuccessful") or {})
        report_reference = successful.get("packageReport")
        if isinstance(report_reference, str):
            report_path = resolve_artifact_reference(solution, report_reference)
            package_report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            partial_package_summary = {
                "status": "partial-package-validated",
                "profile": (state.get("context") or {}).get("workflowProfile"),
                "selectionPlanSha256": package_report.get("selectionPlanSha256"),
                "coverage": package_report.get("selectionSummary"),
                "validationStageStatus": state["stages"]["validation"]["status"],
                "fullyRuntimeQualified": runtime_evidence.get("passed") is True,
                "parityStatus": (
                    (state.get("stages") or {}).get("alertParity") or {}
                ).get("status"),
            }
    return {
        **state,
        "packageFreshness": freshness,
        "runtimeAssessment": {
            "runtimeStatus": (
                "passed"
                if runtime_evidence.get("passed")
                else "source-waived"
                if runtime_evidence.get("sourceStatus") == "source-waived"
                else "blocked"
            ),
            "sourceStatus": runtime_evidence.get("sourceStatus", "not-run"),
            "fullyRuntimeQualified": bool(runtime_evidence.get("passed")),
            "sourceWaiverOnlyBlocker": bool(
                runtime_evidence.get("sourceWaiverOnlyBlocker")
            ),
            "sourceWhitelist": runtime_evidence.get("sourceWhitelist") or [],
            "issues": runtime_evidence.get("issues") or [],
        },
        "authoringSummary": authoring_summary,
        "partialSolution": partial_package_summary,
        "budgetSummary": (
            budget_summary(solution, state["budget"]["campaignId"])
            if state.get("budget") else (
                {
                    "enforcement": "unknown-unmeasured-history",
                    "legacyUsageStatus": "unknown",
                    "message": "This workflow has no persisted campaign budget.",
                }
                if state.get("authoring", {}).get("mode") == "yolo" else None
            )
        ),
        "conversionScope": conversion_scope(solution),
        "statePath": str(existing_artifact_path(solution, STATE_FILE_NAME)),
        "next": next_stage,
    }


def _stop_budget_run(
    state_path: Path,
    state: dict[str, Any],
    stage_name: str,
    reason: str,
) -> None:
    stage = state["stages"][stage_name]
    if stage["status"] == "running":
        stage.update({
            "status": "blocked",
            "completedAt": _utc_now(),
            "message": f"Campaign budget stopped new work: {reason}"[:2000],
        })
    state["workflowStatus"] = "blocked"
    budget = state.get("budget")
    if isinstance(budget, dict):
        budget["status"] = "stopped"
        budget["stopReason"] = reason[:1000]
    authoring = state.get("authoring")
    if isinstance(authoring, dict):
        authoring["status"] = "stopped"
        authoring["stopReason"] = f"Campaign budget: {reason}"[:1000]
    _write_unlocked(state_path, state)


def invalidate_scoped_completion(solution: str | Path) -> None:
    """Retain historical evidence, but never reuse passed stages after a partial refresh."""
    if not existing_artifact_path(solution, STATE_FILE_NAME).is_file():
        return
    with _state_writer_lock(solution) as path:
        loaded_path, state = _load(solution)
        if loaded_path != path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        for name in STAGES[1:]:
            current = state["stages"][name]
            if current["status"] == "passed":
                current["status"] = "blocked"
                current["message"] = (
                    "Rule-scoped conversion invalidated full-solution completion. "
                    "Retained artifacts/evidence are historical; reconvert and revalidate the solution."
                )
        state["workflowStatus"] = "blocked"
        _write_unlocked(path, state)


def invalidate_runtime_completion(
    solution: str | Path,
    changed_queries: list[str],
) -> None:
    """Keep historical reports, but block passed validation after KQL changes."""
    if not changed_queries or not existing_artifact_path(solution, STATE_FILE_NAME).is_file():
        return
    with _state_writer_lock(solution) as path:
        loaded_path, state = _load(solution)
        if loaded_path != path:
            raise ValueError("workflow state selection changed while acquiring its writer lock")
        affected = STAGES[2:]
        if not any(
            state["stages"][name]["status"] not in {"pending", "notRequired"}
            for name in affected
        ):
            return
        names = ", ".join(sorted(set(changed_queries)))
        message = (
            "A converted Advanced Hunting query changed; previous runtime evidence is "
            "historical and must not be reused. Rerun the complete Sentinel and Advanced "
            f"Hunting query families against the exact current queries. Changed outputs: {names}"
        )
        for name in affected:
            current = state["stages"][name]
            if current["status"] not in {"pending", "notRequired"}:
                current["status"] = "blocked"
                current["completedAt"] = None
                current["message"] = message
        state["workflowStatus"] = "blocked"
        _write_unlocked(path, state)


def _dependencies(state: dict[str, Any], stage: str) -> tuple[str, ...]:
    if state["context"]["workflowProfile"] == "authoring":
        return AUTHORING_DEPENDENCIES.get(stage, ())
    return QUALIFICATION_DEPENDENCIES[stage]


def _next_stage_name(state: dict[str, Any]) -> str | None:
    if state.get("authoring", {}).get("status") in {"stopped", "conflicted"}:
        return None
    running = [
        name for name in STAGES if state["stages"][name]["status"] == "running"
    ]
    if running:
        return running[0]
    if (state.get("packaging") or {}).get("pendingReleaseAction"):
        return "packaging"
    for name in STAGES:
        stage = state["stages"][name]
        if (
            name == "validation"
            and _partial_package_state(state)
        ):
            continue
        if stage["status"] in {"passed", "notRequired"}:
            continue
        if all(
            state["stages"][dependency]["status"] == "passed"
            for dependency in _dependencies(state, name)
        ):
            return name
    return None


def _partial_package_state(state: dict[str, Any]) -> bool:
    packaging = (state.get("stages") or {}).get("packaging") or {}
    artifacts = packaging.get("artifacts") or {}
    return (
        packaging.get("status") == "passed"
        and artifacts.get("selectionOutcome") == "partial-package-validated"
    )


def next_workflow_stage(solution: str | Path) -> dict[str, Any]:
    path, state = _load(solution)
    name = _next_stage_name(state)
    freshness = _package_freshness(solution, state)
    release_action_required = bool(freshness and freshness["status"] != "current")
    if release_action_required:
        name = "packaging"
    blocked_by = []
    if name is None and state["workflowStatus"] != "completed":
        for candidate in STAGES:
            if candidate == "validation" and _partial_package_state(state):
                continue
            if state["stages"][candidate]["status"] in {"passed", "notRequired"}:
                continue
            blocked_by.extend(
                dependency
                for dependency in _dependencies(state, candidate)
                if state["stages"][dependency]["status"] != "passed"
            )
            if blocked_by:
                break
    return {
        "runId": state.get("runId"),
        "conversionScope": conversion_scope(solution),
        "solution": state["solution"],
        "statePath": str(existing_artifact_path(solution, STATE_FILE_NAME)),
        "workflowStatus": state["workflowStatus"],
        "next": name,
        "blockedBy": blocked_by,
        "packageFreshness": freshness,
        "releaseActionRequired": release_action_required,
    }


def start_workflow_stage(solution: str | Path, stage: str) -> dict[str, Any]:
    with _state_writer_lock(solution) as path:
        return _start_workflow_stage_unlocked(solution, stage, path)


def _start_workflow_stage_unlocked(
    solution: str | Path,
    stage: str,
    path: Path,
) -> dict[str, Any]:
    if stage not in STAGES:
        raise ValueError(f"unknown workflow stage: {stage}")
    if stage in STAGES[3:]:
        require_solution_conversion_scope(solution)
    loaded_path, state = _load(solution)
    if loaded_path != path:
        raise ValueError("workflow state selection changed while acquiring its writer lock")
    authoring = state.get("authoring")
    if authoring and authoring["status"] in {"stopped", "conflicted"} and stage != "report":
        raise ValueError(
            "YOLO authoring is stopped; new migration stages cannot be started"
        )
    current = state["stages"][stage]
    if current["status"] == "notRequired":
        raise ValueError(
            f"workflow stage is not required for "
            f"{state['context']['workflowProfile']} profile: {stage}"
        )
    if current["status"] == "passed":
        raise ValueError(f"workflow stage already passed: {stage}")
    if current["status"] == "running":
        return {**current, "statePath": str(path), "resumed": True}

    blocked_by = [
        dependency
        for dependency in _dependencies(state, stage)
        if state["stages"][dependency]["status"] != "passed"
    ]
    if blocked_by:
        raise ValueError(
            f"workflow stage {stage} is blocked by: {', '.join(blocked_by)}"
        )
    if state.get("packaging") and stage in {"deployment", "report"}:
        _verify_current_package_state(Path(solution).expanduser().resolve(), state)

    current.update(
        {
            "status": "running",
            "attempts": current["attempts"] + 1,
            "startedAt": _utc_now(),
            "completedAt": None,
            "message": None,
            "artifacts": {},
            "evidence": [],
        }
    )
    state["workflowStatus"] = "inProgress"
    _write_unlocked(path, state)
    return {**current, "statePath": str(path), "resumed": False}


def complete_workflow_stage(
    solution: str | Path,
    stage: str,
    *,
    status: str,
    message: str | None = None,
    artifacts: dict[str, str] | None = None,
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    with _state_writer_lock(solution) as path:
        return _complete_workflow_stage_unlocked(
            solution, stage, path, status=status, message=message,
            artifacts=artifacts, evidence=evidence,
        )


def _complete_workflow_stage_unlocked(
    solution: str | Path,
    stage: str,
    path: Path,
    *,
    status: str,
    message: str | None = None,
    artifacts: dict[str, str] | None = None,
    evidence: list[str] | None = None,
) -> dict[str, Any]:
    if stage not in STAGES:
        raise ValueError(f"unknown workflow stage: {stage}")
    if status not in TERMINAL_STATUSES:
        raise ValueError("stage status must be passed, failed, or blocked")
    if status in {"failed", "blocked"} and not str(message or "").strip():
        raise ValueError(f"{status} workflow stages require a message")
    if status == "passed" and stage != "discovery":
        require_solution_conversion_scope(solution)

    loaded_path, state = _load(solution)
    if loaded_path != path:
        raise ValueError("workflow state selection changed while acquiring its writer lock")
    current = state["stages"][stage]
    if current["status"] != "running":
        raise ValueError(f"workflow stage is not running: {stage}")
    final_artifacts = dict(artifacts or {})
    if stage == "validation" and status == "passed":
        runtime_status = final_artifacts.get("runtimeStatus")
        from .runtime import current_runtime_evidence

        runtime_evidence = current_runtime_evidence(solution)
        if runtime_status == "source-waived":
            if not runtime_evidence.get("sourceWaiverOnlyBlocker"):
                raise ValueError(
                    "source-waived validation requires an exact IdentityInfo source failure "
                    "and every other exact runtime gate to pass"
                )
            _validate_source_waiver_conversion_gates(
                Path(solution).expanduser().resolve(),
                path,
                state,
            )
            whitelist = runtime_evidence.get("sourceWhitelist") or []
            if not whitelist or any(
                item.get("table") != "IdentityInfo"
                or item.get("rawFailure", {}).get("status") != "failed"
                or item.get("applied") is not True
                for item in whitelist
            ):
                raise ValueError(
                    "source-waived validation requires current failed raw results "
                    "classified by the IdentityInfo whitelist"
                )
            final_artifacts.update(
                _source_whitelist_stage_artifacts(runtime_evidence)
            )
            final_artifacts["runtimeStatus"] = "source-waived"
            final_artifacts["sourceRuntimeWhitelistRawStatus"] = "failed"
            final_artifacts.setdefault("sentinelRuntimeProvider", runtime_evidence["sentinelProvider"])
            final_artifacts.setdefault("sentinelRuntimeReport", runtime_evidence["sentinelReport"])
            final_artifacts.setdefault("sentinelRuntimeJson", runtime_evidence["sentinelReport"])
            final_artifacts.setdefault("advancedHuntingRuntimeReport", runtime_evidence["graphReport"])
        elif runtime_status == "environment-blocked":
            if (
                runtime_evidence.get("sourceStatus") == "source-waived"
                or runtime_evidence.get("sourceWhitelist")
            ):
                raise ValueError(
                    "an IdentityInfo source whitelist match cannot be relabeled "
                    "environment-blocked; XDR and source-waiver gates must be evaluated"
                )
            if state["context"]["workflowProfile"] != "authoring":
                raise ValueError(
                    "Qualification validation cannot pass as environment-blocked; "
                    "runtime query validation is required"
                )
            if not str(message or "").strip():
                raise ValueError(
                    "environment-blocked Authoring validation requires an explanation"
                )
            if runtime_evidence.get("currentQueryFailures"):
                raise ValueError(
                    "a current exact-query KQL/runtime failure cannot be relabeled "
                    "environment-blocked: "
                    + "; ".join(runtime_evidence["currentQueryFailures"])
                )
        else:
            if not runtime_evidence["passed"]:
                raise ValueError(
                    "passed validation requires complete Sentinel and Advanced Hunting "
                    "runtime evidence bound to every current query: "
                    + "; ".join(runtime_evidence["issues"])
                )
            final_artifacts.setdefault("sentinelRuntimeProvider", runtime_evidence["sentinelProvider"])
            final_artifacts.setdefault("sentinelRuntimeReport", runtime_evidence["sentinelReport"])
            final_artifacts.setdefault("sentinelRuntimeJson", runtime_evidence["sentinelReport"])
            final_artifacts.setdefault("advancedHuntingRuntimeReport", runtime_evidence["graphReport"])
    elif stage == "validation" and status in {"blocked", "failed"}:
        from .runtime import current_runtime_evidence

        try:
            runtime_evidence = current_runtime_evidence(solution)
        except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
            runtime_evidence = {}
        final_artifacts.update(
            _source_whitelist_stage_artifacts(runtime_evidence)
        )
        if final_artifacts.get("sourceRuntimeWhitelistCount"):
            final_artifacts["sourceRuntimeWhitelistRawStatus"] = "failed"
    if stage == "packaging" and status == "passed":
        _validate_packaging_evidence(state, final_artifacts, solution)
    if (
        status == "passed"
        and stage in {"deployment", "report"}
        and state.get("packaging")
    ):
        _verify_current_package_state(Path(solution).expanduser().resolve(), state)
    current.update(
        {
            "status": status,
            "completedAt": _utc_now(),
            "message": message,
            "artifacts": final_artifacts,
            "evidence": evidence or [],
        }
    )
    if status == "failed":
        state["workflowStatus"] = "failed"
    elif status == "blocked":
        state["workflowStatus"] = "blocked"
    elif stage == "report":
        state["workflowStatus"] = (
            "partialCompleted"
            if _partial_package_state(state)
            else "completed"
        )
    else:
        state["workflowStatus"] = "inProgress"
    _write_unlocked(path, state)
    return {
        **current,
        "statePath": str(path),
        "workflowStatus": state["workflowStatus"],
        "next": _next_stage_name(state),
    }
