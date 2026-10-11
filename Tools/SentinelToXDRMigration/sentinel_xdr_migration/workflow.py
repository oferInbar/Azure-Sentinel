from __future__ import annotations

import json
import hashlib
import os
import re
import tempfile
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
from .authoring_contract import (
    AUTHORING_SCHEMA_VERSION,
    AuthoringContractError,
    calculate_inventory_sha256,
    seal_authoring_contract,
    validate_authoring_contract,
)
from .content_paths import content_path
from .converter import (
    SOURCE_ID_PATTERN,
    analytic_rule_files,
    inspect_solution,
    convert_solution,
    validate_solution,
    solution_paths,
)
from .target_context import build_target, write_target

STATE_FILE_NAME = "workflow-state.json"
SCHEMA_VERSION = "1.1.0"
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
            "log-analytics-cli": rule["querySha256"],
            "graph": target.get("querySha256") or "",
        }

    runtime_findings: dict[str, list[dict[str, Any]]] = {
        rule["ruleId"]: [] for rule in inventory
    }
    environment_errors: list[dict[str, Any]] = []
    environment_keys: set[tuple[str, str]] = set()
    all_reports_passed = True
    for provider in ("triage-mcp", "log-analytics-cli", "graph"):
        report_path = run_directory / f"runtime-validation.{provider}.json"
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
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"existing {provider} runtime report contains a malformed result")
            detection = str(entry.get("detection") or "").replace("\\", "/")
            if detection in names:
                raise ValueError(f"existing {provider} runtime report duplicates {detection}")
            names.add(detection)
            rule_id = detection_to_rule.get(detection)
            if rule_id is None:
                continue
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
            message = str(entry.get("error") or f"{provider} reported {status}")
            runtime_findings[rule_id].append({
                "findingId": f"runtime-{provider}-{len(runtime_findings[rule_id]) + 1}",
                "kind": "error",
                "message": message,
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
            "mappingAssumptions": list(prior.get("mappingAssumptions") or []),
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


def _current_runtime_status(
    solution: Path,
    profile: str,
    record: dict[str, Any],
) -> tuple[str, str | None, dict[str, Any]]:
    from .runtime import current_runtime_evidence

    evidence = current_runtime_evidence(solution)
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
    status, message, _ = _current_runtime_status(
        solution, state["context"]["workflowProfile"], record
    )
    if status not in {"passed", "environment-blocked"}:
        return state
    _start_workflow_stage_unlocked(solution, "validation", state_path)
    artifacts = {"runtimeStatus": status} if status == "environment-blocked" else {}
    _complete_workflow_stage_unlocked(
        solution,
        "validation",
        state_path,
        status="passed",
        message=message,
        artifacts=artifacts,
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

            discovery = state["stages"]["discovery"]
            if discovery["status"] != "passed":
                if discovery["status"] != "running":
                    _start_workflow_stage_unlocked(root, "discovery", state_path)
                inspection = inspect_solution(root)
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
                try:
                    conversion = convert_solution(root)
                    _verify_source_inventory(root, record)
                    manifest = _read_full_conversion_manifest(
                        root, state_path.parent, inventory
                    )
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
            validation = validate_solution(root)
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
        run = create_run(root)
        with using_run(root, run.name):
            return initialize_workflow(
                root, tenant_id=tenant_id, subscription_id=subscription_id,
                workspace_resource_id=workspace_resource_id,
                workspace_customer_id=workspace_customer_id, version_bump=version_bump,
                workflow_profile=workflow_profile, yolo=yolo,
            )
    existing_path = existing_artifact_path(root, STATE_FILE_NAME)
    if existing_path.exists():
        with _run_writer_lock(existing_path.parent):
            path, state = _load(root)
            if yolo is True and "authoring" not in state:
                raise ValueError(
                    "YOLO cannot be enabled on an existing legacy run; initialize a new run explicitly"
                )
            context = state["context"]
            for key, value in requested_context.items():
                if key == "targetContextLocked":
                    if value:
                        context[key] = True
                    continue
                if value is not None and context.get(key) not in (None, value):
                    raise ValueError(
                        f"workflow already uses {key}={context.get(key)!r}, "
                        f"not {value!r}"
                    )
                if value is not None and context.get(key) is None:
                    context[key] = value
            _select_workflow_profile(state, workflow_profile)
            _write_unlocked(path, state)
            if target:
                write_target(root, target)
            if "authoring" in state:
                _recover_yolo_state(root, path, state)
            return {
                **state,
                "statePath": str(path),
                "resumed": True,
                "next": _next_stage_name(state),
            }

    frozen_inventory = _source_inventory(root) if yolo is True else None
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
        _persist_contract_snapshot(
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
    for name in ("mainTemplate", "createUiDefinition", "testParameters", "zip"):
        value = artifacts.get(name) or report.get(name)
        if not value or not resolve_artifact_reference(solution, value).is_file():
            raise ValueError(f"V3.1 packaging evidence is missing artifact: {name}")
    requested_bump = state["context"].get("versionBump")
    if requested_bump is not None and report.get("versionBump") != requested_bump:
        raise ValueError(
            "V3.1 package report version bump does not match workflow context: "
            f"{report.get('versionBump')!r} != {requested_bump!r}"
        )


def workflow_status(solution: str | Path) -> dict[str, Any]:
    path, state = _load(solution)
    authoring_summary = None
    if state.get("authoring"):
        document, _ = _load_contract_snapshot(path.parent, state["authoring"]["currentContract"])
        authoring_summary = {
            "status": state["authoring"]["status"],
            "contract": state["authoring"]["currentContract"],
            "coverage": document["coverage"],
            "inventorySha256": document["inventory"]["sha256"],
        }
    return {
        **state,
        "authoringSummary": authoring_summary,
        "conversionScope": conversion_scope(solution),
        "statePath": str(existing_artifact_path(solution, STATE_FILE_NAME)),
        "next": _next_stage_name(state),
    }


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
    for name in STAGES:
        stage = state["stages"][name]
        if stage["status"] in {"passed", "notRequired"}:
            continue
        if all(
            state["stages"][dependency]["status"] == "passed"
            for dependency in _dependencies(state, name)
        ):
            return name
    return None


def next_workflow_stage(solution: str | Path) -> dict[str, Any]:
    path, state = _load(solution)
    name = _next_stage_name(state)
    blocked_by = []
    if name is None and state["workflowStatus"] != "completed":
        for candidate in STAGES:
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
        if runtime_status == "environment-blocked":
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
            final_artifacts.setdefault("advancedHuntingRuntimeReport", runtime_evidence["graphReport"])
    if stage == "packaging" and status == "passed":
        _validate_packaging_evidence(state, final_artifacts, solution)
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
        state["workflowStatus"] = "completed"
    else:
        state["workflowStatus"] = "inProgress"
    _write_unlocked(path, state)
    return {
        **current,
        "statePath": str(path),
        "workflowStatus": state["workflowStatus"],
        "next": _next_stage_name(state),
    }
