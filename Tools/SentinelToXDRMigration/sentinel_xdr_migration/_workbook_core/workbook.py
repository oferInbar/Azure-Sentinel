"""Offline, loss-aware Notebook/1.0 adapter around the shared KQL migrator."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
from typing import Iterator

from . import migrator, rewrite

AH = "advancedHunting"
LA = "microsoft.operationalinsights/workspaces"
SCOPE_KEYS = {
    "crossComponentResources", "fallbackResourceIds", "resourceIds",
    "workspaceId", "workspaceResourceId", "selectedWorkspaceIds",
}
PARAMETER_KEYS = {
    "parameterName", "exportParameterName", "timeContextFromParameter",
    "resourceContextFromParameter",
}
TOKEN = re.compile(r"\{([A-Za-z_][\w .-]*)(?::[^{}]*)?\}")


def walk(value, path="") -> Iterator[tuple[str, dict]]:
    """Yield dictionaries with RFC 6901 JSON pointers, including nested groups."""
    if isinstance(value, dict):
        yield path, value
        for key, child in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            yield from walk(child, f"{path}/{escaped}")
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from walk(child, f"{path}/{i}")


def query_hash(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def references(value, *, skip_scope=False) -> set[str]:
    found = set()
    if isinstance(value, str):
        found.update(TOKEN.findall(value))
    elif isinstance(value, list):
        for child in value:
            found.update(references(child, skip_scope=skip_scope))
    elif isinstance(value, dict):
        for key, child in value.items():
            if skip_scope and (key in SCOPE_KEYS or key == "resourceContextFromParameter"):
                continue
            if key in PARAMETER_KEYS and isinstance(child, str):
                found.add(child)
            if key == "linkTarget" and child == "parameter":
                found.add(value.get("cellValue", ""))
            found.update(references(child, skip_scope=skip_scope))
    return found


def query_surfaces(doc: dict) -> list[dict]:
    """Inventory every nonempty query, honoring inherited provider settings."""
    result = []

    def visit(value, path="", inherited=None, parameter=False):
        if isinstance(value, dict):
            settings = dict(inherited or {})
            settings.update({k: value[k] for k in ("queryType", "resourceType") if k in value})
            if "query" in value and value["query"] not in ("", None):
                result.append({
                    "path": path + "/query", "node": value,
                    "queryType": settings.get("queryType", 0),
                    "resourceType": settings.get("resourceType"),
                    "parameter": parameter,
                })
            for key, child in value.items():
                escaped = key.replace("~", "~0").replace("/", "~1")
                visit(child, f"{path}/{escaped}", settings,
                      parameter or key == "parameters")
        elif isinstance(value, list):
            for i, child in enumerate(value):
                visit(child, f"{path}/{i}", inherited, parameter)

    visit(doc)
    return result


def _scope_parameters(doc, protected=()):
    entries = [(path, node) for path, node in walk(doc)
               if re.search(r"/parameters/\d+$", path) and node.get("name")]
    names = {node["name"] for _, node in entries}
    if len(names) != len(entries):
        raise ValueError("Duplicate parameter names: scope dependencies are ambiguous.")
    params = {node["name"]: node for _, node in entries}
    nodes = dict(walk(doc))
    inherited_resources = {}
    for path, p in entries:
        ancestor = path
        while True:
            if nodes.get(ancestor, {}).get("resourceType"):
                inherited_resources[p["name"]] = nodes[ancestor]["resourceType"].lower()
                break
            if not ancestor:
                break
            ancestor = ancestor.rsplit("/", 1)[0]
    surfaces = {id(s["node"]): s for s in query_surfaces(doc)}
    bindings = set()
    for _, node in walk(doc):
        for key in SCOPE_KEYS | {"resourceContextFromParameter"}:
            if key in node:
                bindings |= references({key: node[key]})
    dependencies = {
        name: references(p, skip_scope=surfaces.get(id(p), {}).get("queryType", 0)
                         in (0, None, AH)) & names
        for name, p in params.items()
    }
    all_dependencies = {name: references(p) & names for name, p in params.items()}

    def eligible(name):
        p = params[name]
        # A type-5 parameter may be a KQL-backed Computer filter, not a workspace.
        qt = surfaces.get(id(p), {}).get("queryType")
        return not (p.get("query") and qt in (0, None, AH)) and p.get("type") != 4

    candidates = {
        name for name, p in params.items()
        if eligible(name) and (
            p.get("type") == 6
            or (p.get("type") == 5 and (
                name in bindings or inherited_resources.get(name) == LA))
            or LA in json.dumps(p.get("typeSettings", {})).lower()
            or (p.get("queryType") == 1 and LA in p.get("query", "").lower())
        )
    }
    # Include both upstream scope helpers and hidden derived helpers (ContextFree).
    while True:
        expanded = candidates | {
            dep for name in candidates for dep in all_dependencies[name] if eligible(dep)
        } | {
            name for name, p in params.items()
            if eligible(name) and p.get("isHiddenWhenLocked")
            and all_dependencies[name] & candidates
        }
        if expanded == candidates:
            break
        candidates = expanded

    outside = copy.deepcopy(doc)
    for _, node in walk(outside):
        if isinstance(node.get("parameters"), list):
            node["parameters"] = []
    live = ((names - candidates) | (references(outside, skip_scope=True) & names)
            | (set(protected) & names))
    while True:
        expanded = live | {
            dep for name in live
            for dep in (all_dependencies[name] if name in candidates else dependencies[name])
        }
        if expanded == live:
            break
        live = expanded
    removed = candidates - live
    return entries, removed, candidates & live


def _raw_query(query, query_type):
    if not isinstance(query, str):
        raise ValueError("query must be a string")
    if query_type == AH and query.lstrip().startswith("{"):
        try:
            settings = json.loads(query)
        except ValueError as exc:
            raise ValueError("Malformed Advanced Hunting settings wrapper") from exc
        if not isinstance(settings, dict) or settings.get("__advancedHuntingSettings") is not True:
            raise ValueError("Unrecognized Advanced Hunting query wrapper")
        if set(settings) - {"__advancedHuntingSettings", "query", "selectedWorkspaceIds"}:
            raise ValueError("Unknown Advanced Hunting wrapper settings; review before removing")
        if not isinstance(settings.get("query"), str):
            raise ValueError("Advanced Hunting wrapper has no string query")
        return settings["query"]
    return query


def convert_workbook(source: dict, resolutions: dict | None = None,
                     tables: list[str] | None = None) -> dict:
    """Return an intact review draft and report. Never resolves or executes live.

    resolutions maps original query pointers to {querySha256, tables, evidence}.
    tables is an explicit caller-reviewed fallback, NOT a discovered table list.
    """
    if source.get("version") != "Notebook/1.0" or not isinstance(source.get("items"), list):
        raise ValueError("Expected a Notebook/1.0 document with an items array.")
    doc = copy.deepcopy(source)
    originals = query_surfaces(source)
    surfaces = query_surfaces(doc)
    entries, removed, retained_scope = _scope_parameters(doc)
    removed_prefixes = [path + "/" for path, p in entries if p["name"] in removed]
    issues, reports, gates = [], [], set()

    def issue(path, code, message):
        issues.append({"path": path, "code": code, "message": message})

    for path, p in entries:
        if p["name"] in retained_scope:
            issue(path, "scope-used-by-content",
                  f"{p['name']} is used by retained business content or a drilldown. "
                  "Retained; manually replace its Azure scope semantics.")

    converted_nodes = set()
    for surface, original in zip(surfaces, originals):
        path, node, qt = surface["path"], surface["node"], surface["queryType"]
        if any(path.startswith(prefix) for prefix in removed_prefixes):
            reports.append({"sourcePath": path, "status": "removed-scope-helper"})
            continue
        entry = {"sourcePath": path, "parameter": surface["parameter"]}
        reports.append(entry)
        if qt not in (0, None, AH) or (
            qt != AH and (surface["resourceType"] or "").lower() not in ("", LA)
        ):
            entry["status"] = "blocked"
            issue(path, "unsupported-provider",
                  f"Provider {qt!r}/{surface['resourceType']!r} is retained unchanged; "
                  "supply a reviewed provider migration.")
            continue
        try:
            raw = _raw_query(node["query"], qt)
        except ValueError as exc:
            entry["status"] = "blocked"
            issue(path, "query-format", str(exc))
            continue
        code = "".join(text if kind == "code" else " " * len(text)
                       for kind, text in rewrite._segments(raw))
        if re.search(r"\b(?:workspace|app|resource|cluster|database)\s*\(", code,
                     re.IGNORECASE):
            entry["status"] = "blocked"
            issue(path, "explicit-scope-function",
                  "Explicit workspace/app/resource/cluster/database function cannot be "
                  "replaced by blank AH selection. Keep this panel and review its sources.")
            continue
        source_calls = set(re.findall(
            r"(?:^|;)\s*([A-Za-z_]\w*)\s*\(|\binvoke\s+([A-Za-z_]\w*)", code))
        opaque = {name for pair in source_calls for name in pair if name} - {
            "datatable", "range", "print",
        }
        if opaque:
            entry["status"] = "blocked"
            issue(path, "saved-function",
                  f"Source function(s) {', '.join(sorted(opaque))} need a reviewed AH "
                  "definition and source evidence. Inline and validate; do not fabricate tables.")
            continue
        evidence = (resolutions or {}).get(path)
        resolved = tables
        entry["resolutionEvidence"] = "caller-reviewed tables" if tables is not None else None
        if evidence is not None:
            if (not isinstance(evidence, dict)
                    or evidence.get("querySha256") != query_hash(original["node"]["query"])
                    or not isinstance(evidence.get("tables"), list)
                    or not all(isinstance(t, str) and t for t in evidence["tables"])
                    or not evidence.get("evidence")):
                entry["status"] = "blocked"
                issue(path, "stale-resolution",
                      "Supply tables, evidence and matching SHA256 of the raw query at this path.")
                continue
            resolved = evidence["tables"]
            entry["resolutionEvidence"] = evidence["evidence"]
        contract = migrator.convert(raw, tables=resolved, source_id=path,
                                    artifact_type="workbook", resolve=False)
        entry["conversion"] = contract
        entry["status"] = contract["status"]
        if contract["status"] == "blocked" or resolved is None:
            issue(path, "mapping-or-resolution",
                  contract["blockedReason"] or
                  "No offline source evidence. Supply --resolutions (per-path query hash, "
                  "tables and evidence) or --tables after reviewing ALL query sources.")
            continue
        if contract["unsupported"] or contract["status"] == "needs-review":
            issue(path, "query-review",
                  "; ".join(x["reason"] for x in contract["unsupported"])
                  or "Shared migrator requires source/mapping review; conversion is not deterministic.")
        node["query"] = contract["convertedKql"]
        node["queryType"] = AH
        converted_nodes.add(id(node))
        if surface["parameter"]:
            gates.add("ah-query-backed-parameters")
        # The mapping catalog's resolve-to-self does not establish blank-selection visibility.
        gates.add("blank-ah-selection-table-visibility")
        if references(raw) - references(node["query"]):
            raise AssertionError(f"Parameter templates lost at {path}")

    # Blocked panels keep the scope inputs they still need. Revisit the graph
    # before removing any helper; an unsupported sibling is not disposable.
    blocked = [s for s, r in zip(surfaces, reports) if r["status"] == "blocked"
               or (id(s["node"]) not in converted_nodes
                   and r["status"] != "removed-scope-helper")]
    if blocked:
        protected = set()
        nodes = dict(walk(doc))
        for surface in blocked:
            protected |= references(surface["node"])
            ancestor = surface["path"].rsplit("/", 1)[0]
            while True:
                node = nodes.get(ancestor, {})
                for key in SCOPE_KEYS | {"resourceContextFromParameter"}:
                    if key in node:
                        protected |= references({key: node[key]})
                if not ancestor:
                    break
                ancestor = ancestor.rsplit("/", 1)[0]
        entries, removed, retained_scope = _scope_parameters(doc, protected)
        removed_prefixes = [path + "/" for path, p in entries if p["name"] in removed]
        for surface, entry in zip(surfaces, reports):
            if entry["status"] == "removed-scope-helper" and not any(
                surface["path"].startswith(prefix) for prefix in removed_prefixes
            ):
                entry["status"] = "retained-scope-helper"
                issue(surface["path"], "blocked-panel-scope",
                      "Helper retained because an unsupported panel still needs its scope.")

    # Keep item arrays and layout untouched, including now-empty parameter groups.
    for _, node in walk(doc):
        if isinstance(node.get("parameters"), list):
            node["parameters"] = [p for p in node["parameters"]
                                  if p.get("name") not in removed]

    retained_scope_nodes = {id(p) for _, p in entries if p["name"] in retained_scope}

    def clean(value, path=""):
        if isinstance(value, dict):
            descendants = query_surfaces(value)
            safe = all(id(s["node"]) in converted_nodes for s in descendants)
            binding_container = (
                bool(descendants) or not path
                or "parameters" in value or "items" in value
                or re.search(r"/parameters/\d+$", path)
                or str(value.get("version", "")).startswith(("KqlItem/", "KqlParameterItem/",
                                                            "NotebookGroup/"))
            )
            if id(value) in converted_nodes or (
                safe and binding_container and id(value) not in retained_scope_nodes
            ):
                for key in SCOPE_KEYS | {"resourceContextFromParameter"}:
                    value.pop(key, None)
                if value.get("resourceType", "").lower() in (
                    LA, "microsoft.resourcegraph/resources", "microsoft.insights/components"
                ):
                    value.pop("resourceType", None)
                if "parameters" in value or "items" in value:
                    value.pop("queryType", None)
                context = value.get("context")
                if isinstance(context, dict) and isinstance(context.get("ownerId"), str):
                    owner = context["ownerId"]
                    if "/subscriptions/" in owner.lower() or references(owner) & removed:
                        context.pop("ownerId")
            for key, child in list(value.items()):
                clean(child, path + "/" + key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                clean(child, f"{path}/{index}")

    clean(doc)
    output_paths = {id(s["node"]): s["path"] for s in query_surfaces(doc)}
    for surface, entry in zip(surfaces, reports):
        entry["outputPath"] = output_paths.get(id(surface["node"]))
    return {
        "workbook": doc,
        "report": {
            "status": "blocked" if issues else ("needs-validation" if gates else "converted"),
            "queries": reports,
            "removedParameters": [{"name": p["name"], "sourcePath": path}
                                  for path, p in entries if p["name"] in removed],
            "issues": issues,
            "gates": [{"code": gate, "status": "unverified"} for gate in sorted(gates)],
            "validation": {"localStructureOnly": True, "runtime": "not-run", "ui": "not-run"},
        },
    }
