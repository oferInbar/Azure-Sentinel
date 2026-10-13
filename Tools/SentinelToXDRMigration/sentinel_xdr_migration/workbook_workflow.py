from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .artifacts import (
    existing_artifact_path,
    report_directory,
    resolve_artifact_reference,
)
from .content_paths import content_path


CAPABILITY_VERSION = 1
ARM_VALIDATION_METHODS = ("arm-ttk", "lab-deployment")


def enabled(state: dict[str, Any]) -> bool:
    return state.get("context", {}).get("workbookCapabilityVersion") == CAPABILITY_VERSION


def has_analytic_rules(solution: str | Path) -> bool:
    root = Path(solution).expanduser().resolve()
    from .converter import analytic_rule_files

    return (
        any((root / name).is_dir() for name in ("Analytic Rules", "Analytics Rules"))
        and bool(analytic_rule_files(root))
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _inventory(solution: Path) -> list[dict[str, str]]:
    from .workbooks import inventory_workbooks

    rows = inventory_workbooks(solution)
    inventory = [
        {"path": row["path"], "sha256": row["sha256"]}
        for row in rows
    ]
    inventory.sort(key=lambda row: row["path"])
    if len({row["path"] for row in inventory}) != len(inventory):
        raise ValueError("workbook inventory contains duplicate source paths")
    return inventory


def _data(solution: Path) -> tuple[Path, dict[str, Any]]:
    from .packaging import _read_json, _solution_data_file

    path = _solution_data_file(solution / "Data")
    return path, _read_json(path)


def selected_workbook_references(
    solution: str | Path,
    document: dict[str, Any] | None = None,
) -> list[Path]:
    root = Path(solution).expanduser().resolve()
    from .packaging import _solution_relative_reference

    if document is None:
        _, document = _data(root)
    keys = [key for key in document if key.casefold() == "xdr workbooks"]
    if len(keys) > 1:
        raise ValueError("solution Data has duplicate XDR Workbooks selection keys")
    if not keys:
        return []
    references = document[keys[0]]
    if isinstance(references, str):
        references = json.loads(references)
    if not isinstance(references, list) or any(
        not isinstance(reference, str) or not reference.strip()
        for reference in references
    ):
        raise ValueError("solution Data XDR Workbooks must be a content-reference array")
    paths = [
        _solution_relative_reference(root, reference, "XDR Workbooks")
        for reference in references
    ]
    if len(set(paths)) != len(paths):
        raise ValueError("solution Data selects the same Defender workbook more than once")
    for path in paths:
        if not path.is_relative_to(root / "XDR Workbooks") or path.suffix.lower() != ".json":
            raise ValueError("XDR Workbooks selections must reference authored workbook JSON")
    return paths


def freeze_inventory(solution: str | Path) -> dict[str, Any]:
    root = Path(solution).expanduser().resolve()
    inventory = _inventory(root)
    included = [row["path"] for row in inventory]
    excluded: list[dict[str, str]] = []
    if (root / "Data").is_dir():
        _, document = _data(root)
        if any(key.casefold() == "xdr workbooks" for key in document):
            included = []
            known_sources = {row["path"] for row in inventory}
            for path in selected_workbook_references(root, document):
                target = json.loads(path.read_text(encoding="utf-8-sig"))
                source = target.get("contentProvenance", {}).get("source", {}).get("path")
                if source not in known_sources or source in included:
                    raise ValueError("explicit workbook selection does not match the source inventory")
                included.append(source)
            excluded = [
                {"path": row["path"], "reason": "Excluded by the explicit solution Data selection."}
                for row in inventory
                if row["path"] not in included
            ]
    return {
        "schemaVersion": "1.0.0",
        "inventory": inventory,
        "inventorySha256": _digest(inventory),
        "selection": {"included": sorted(included), "excluded": excluded},
    }


def verify_inventory(solution: str | Path, state: dict[str, Any]) -> None:
    if not enabled(state):
        return
    frozen = state["workbooks"]
    current = _inventory(Path(solution).expanduser().resolve())
    if current != frozen["inventory"] or _digest(current) != frozen["inventorySha256"]:
        raise ValueError(
            "frozen workbook inventory changed; preserve this run and initialize a new run"
        )
    selection = frozen["selection"]
    included = selection["included"]
    excluded = [row["path"] for row in selection["excluded"]]
    if (
        len(set(included + excluded)) != len(included + excluded)
        or set(included + excluded) != {row["path"] for row in current}
        or any(not row["reason"].strip() for row in selection["excluded"])
    ):
        raise ValueError("workbook selection must account for the entire frozen inventory")


def bind_conversion(
    solution: str | Path,
    state: dict[str, Any],
) -> dict[str, str]:
    if not enabled(state):
        return {}
    verify_inventory(solution, state)
    if not state["workbooks"]["inventory"]:
        return {}
    root = Path(solution).expanduser().resolve()
    path = report_directory(root) / "workbooks-manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    inventory = {row["path"]: row["sha256"] for row in state["workbooks"]["inventory"]}
    results = manifest.get("results")
    if (
        not isinstance(results, list)
        or any(not isinstance(row, dict) for row in results)
        or len(results) != len(inventory)
        or {row.get("sourceRelativePath") for row in results} != set(inventory)
    ):
        raise ValueError("workbook conversion manifest must retain the complete frozen inventory")
    for row in results:
        if row.get("sourceSha256") != inventory[row["sourceRelativePath"]]:
            raise ValueError("workbook conversion manifest has stale source evidence")
        if row.get("status") == "converted":
            output = content_path(root, row["outputRelativePath"])
            if (
                not output.is_relative_to(root / "XDR Workbooks")
                or not output.is_file()
                or hashlib.sha256(output.read_bytes()).hexdigest() != row.get("outputSha256")
            ):
                raise ValueError("workbook conversion manifest has stale target evidence")
    return {
        "workbookManifest": str(path),
        "workbookManifestSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "workbookSelectionSha256": _digest(state["workbooks"]["selection"]),
    }


def validate_evidence(solution: str | Path, state: dict[str, Any]) -> dict[str, Any]:
    if not enabled(state):
        return {"total": 0, "valid": 0, "invalid": 0, "results": []}
    root = Path(solution).expanduser().resolve()
    current = bind_conversion(root, state)
    recorded = state["stages"]["conversion"].get("artifacts") or {}
    if any(current[key] != recorded.get(key) for key in current):
        raise ValueError("workbook conversion evidence is missing, changed, or bound to another selection")
    included = state["workbooks"]["selection"]["included"]
    if not state["workbooks"]["inventory"]:
        return {"total": 0, "valid": 0, "invalid": 0, "results": []}
    manifest_path = resolve_artifact_reference(root, current["workbookManifest"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    selected = [
        row for row in manifest["results"] if row["sourceRelativePath"] in included
    ]
    if any(
        row.get("status") != "converted" or row.get("reviewRequired") is not False
        for row in selected
    ):
        raise ValueError("selected workbooks have unresolved conversion or review blockers")
    expected = {content_path(root, row["outputRelativePath"]) for row in selected}
    if set(selected_workbook_references(root)) != expected:
        raise ValueError("solution Data workbook selection differs from the frozen reviewed selection")
    from .workbooks import validate_workbooks

    result = validate_workbooks(root, selected_only=True)
    if (
        result.get("total") != len(selected)
        or result.get("valid") != len(selected)
        or result.get("invalid") != 0
        or len(result.get("results") or []) != len(selected)
        or any(row.get("valid") is not True for row in result.get("results") or [])
    ):
        raise ValueError("selected workbooks must individually pass current structural validation")
    return result


def current_state(solution: str | Path) -> dict[str, Any] | None:
    path = existing_artifact_path(solution, "workflow-state.json")
    if not path.is_file():
        return None
    from .workflow import _load

    return _load(solution)[1]


def summary(solution: str | Path, state: dict[str, Any]) -> dict[str, Any] | None:
    if not enabled(state):
        return None
    workbook_state = state["workbooks"]
    return {
        "inventoryCount": len(workbook_state["inventory"]),
        "selectedCount": len(workbook_state["selection"]["included"]),
        "excluded": workbook_state["selection"]["excluded"],
        "inventorySha256": workbook_state["inventorySha256"],
        "armValidationMethod": state["context"]["armValidationMethod"],
        "contractSupport": "unverified",
    }
