"""Deterministic Sentinel -> Advanced Hunting KQL rewriter (Migrator core, step 3).

Given a Sentinel KQL query and the tables it resolves to, apply the catalog's
deterministic transforms and return the converted KQL plus a reviewable diff.

What it does (safe, semantics-preserving only):
  * table renames        - when the AH table name differs (Wave-2; none for Wave 1).
  * column renames        - per-table renames from the mapping catalog. There is no
                            global time-column rename: `TimeGenerated` exists in AH
                            unchanged (it must NOT be rewritten to `Timestamp`).
Replacements are whole-identifier and skip string literals and `//` comments, so
tokens inside strings/comments are never touched.

What it deliberately does NOT do:
  * It never silently deletes columns. References to Log-Analytics-only columns
    (`TenantId`, `_ResourceId`, ...) that don't exist in AH are *flagged* for
    review, not removed - deleting them would change query semantics. The Judge's
    static bind independently confirms whether the converted query binds in AH.

Overall tier (worst across the query's tables) drives the caller's status:
  1to1     - all tables 1:1 and no LA-only-column references -> deterministic, high confidence.
  renamed / merged - needs review (Wave-2, out of v1 conversion scope).
  blocked  - a table has no AH equivalent -> do not convert.

    python rewrite.py --query "DeviceProcessEvents | where TimeGenerated > ago(1d)" \
                      --tables DeviceProcessEvents
    python rewrite.py --file rule.kql --resolve      # resolve tables live via Log Analytics
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# [ASIM-FIX-TAG 2026-08-03] Previously deliberately disabled (user decision, 2026-08-03):
# live testing on Zava (a unified-SecOps tenant) confirmed _Im_WebSession/_Im_FileEvent/
# _Im_Dns DO resolve and return correctly-shaped ASIM data there - but only because
# that tenant links its Sentinel workspace's saved ASIM functions into AH. Generic E5
# customers (this tool's actual target, per Business background and goal.md) are not
# guaranteed to be unified or have ASIM parsers installed, and the whole point of this
# migration is to reduce their dependency on Sentinel - so relying on `_Im_*` resolving
# was seen as at odds with the tool's own goal.
# [ASIM-FIX-TAG 2026-08-03g] Re-enabled (user decision, 2026-08-03): the mapping_catalog.json
# `asimFunctionRewrites.functions` targets were corrected to route _Im_NetworkSession/
# _Im_WebSession/_Im_FileEvent/_Im_Dns to their live-callable `_Im_<Schema>BuiltIn` AH
# functions (rather than the plain, unreliable ASim<Schema>Logs tables), and these are
# now verified to work - so the rewrite is turned back on.
ASIM_REWRITE_ENABLED = True

from . import mapping_catalog, dynamic_casts, asim_functions

_TIER_RANK = {"1to1": 0, "renamed": 1, "merged": 1, "unknown": 2, "blocked": 3}


def _segments(kql: str) -> List[Tuple[str, str]]:
    """Split KQL into ('code'|'str'|'comment', text) segments so renames only
    touch code. Handles `//` line comments, '...'/"..." string literals with
    backslash escapes, and `@"..."` verbatim strings (no escape)."""
    segs: List[Tuple[str, str]] = []
    i, n, start = 0, len(kql), 0
    while i < n:
        c = kql[i]
        if c == "/" and i + 1 < n and kql[i + 1] == "/":
            if start < i:
                segs.append(("code", kql[start:i]))
            j = kql.find("\n", i)
            if j == -1:
                j = n
            segs.append(("comment", kql[i:j]))
            i = start = j
        elif c == '"' or c == "'":
            if start < i:
                segs.append(("code", kql[start:i]))
            verbatim = i > 0 and kql[i - 1] == "@"
            quote, j = c, i + 1
            while j < n:
                if not verbatim and kql[j] == "\\":
                    j += 2
                    continue
                if kql[j] == quote:
                    j += 1
                    break
                j += 1
            segs.append(("str", kql[i:j]))
            i = start = j
        else:
            i += 1
    if start < n:
        segs.append(("code", kql[start:n]))
    return segs


def _apply_renames(kql: str, rename_map: Dict[str, str]) -> Tuple[str, Dict[str, int]]:
    """Whole-identifier replace every key with its value, in code segments only.
    Returns (new_kql, {source_token: count})."""
    if not rename_map:
        return kql, {}
    keys = sorted(rename_map, key=len, reverse=True)
    pat = re.compile(r"\b(" + "|".join(re.escape(k) for k in keys) + r")\b")
    counts: Dict[str, int] = {}

    def repl(m: "re.Match") -> str:
        k = m.group(1)
        counts[k] = counts.get(k, 0) + 1
        return rename_map[k]

    out = []
    for kind, text in _segments(kql):
        out.append(pat.sub(repl, text) if kind == "code" else text)
    return "".join(out), counts


def _find_identifiers(kql: str, names: set) -> set:
    """Return which of `names` appear as whole identifiers in code segments."""
    if not names:
        return set()
    pat = re.compile(r"\b(" + "|".join(re.escape(k) for k in names) + r")\b")
    found = set()
    for kind, text in _segments(kql):
        if kind == "code":
            found.update(m.group(1) for m in pat.finditer(text))
    return found


def _code_mask(kql: str) -> List[bool]:
    """Boolean mask, True where the char is in a code segment (not string/comment)."""
    mask: List[bool] = []
    for kind, text in _segments(kql):
        mask.extend([kind == "code"] * len(text))
    return mask


def _is_word(kql: str, start: int, end: int) -> bool:
    """True if kql[start:end] is bounded by non-identifier chars (whole word)."""
    before = kql[start - 1] if start > 0 else ""
    after = kql[end] if end < len(kql) else ""
    return not (before.isalnum() or before == "_") and not (after.isalnum() or after == "_")


_OPEN, _CLOSE = "([{", ")]}"


def _dedupe_key_region(region: str, mask: List[bool], offset: int) -> Tuple[str, List[str]]:
    """Split a `by` group-key region on top-level commas and drop exact
    (whitespace-normalized) duplicate keys, preserving order and outer spacing."""
    parts: List[str] = []
    depth, start = 0, 0
    for idx in range(len(region)):
        if not mask[offset + idx]:
            continue
        c = region[idx]
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(region[start:idx])
            start = idx + 1
    parts.append(region[start:])

    seen: set = set()
    unique: List[str] = []
    removed: List[str] = []
    for p in parts:
        norm = re.sub(r"\s+", " ", p.strip()).lower()
        if not norm:
            continue
        if norm in seen:
            removed.append(p.strip())
            continue
        seen.add(norm)
        unique.append(p.strip())
    if not removed:
        return region, []
    lead = region[:len(region) - len(region.lstrip())]
    trail = region[len(region.rstrip()):]
    return lead + ", ".join(unique) + trail, removed


def _dedupe_summarize_keys(kql: str) -> Tuple[str, List[str]]:
    """Remove exact-duplicate group-by keys from every `summarize ... by ...`
    clause. Repeated keys are redundant and make AH reject the query with
    'Duplicate column name(s)'. Whole-identifier / paren-aware and skips
    strings & comments, so it is safe and semantics-preserving."""
    mask = _code_mask(kql)
    n = len(kql)
    lower = kql.lower()
    repls: List[Tuple[int, int, str]] = []
    removed_all: List[str] = []

    depth, i = 0, 0
    while i < n:
        if mask[i]:
            c = kql[i]
            if c in _OPEN:
                depth += 1
            elif c in _CLOSE:
                depth -= 1
            elif depth == 0 and lower.startswith("summarize", i) and _is_word(kql, i, i + 9):
                # Statement runs until the next top-level pipe (or end of query).
                j, d2, stmt_end = i + 9, 0, n
                while j < n:
                    if mask[j]:
                        cj = kql[j]
                        if cj in _OPEN:
                            d2 += 1
                        elif cj in _CLOSE:
                            d2 -= 1
                        elif cj == "|" and d2 == 0:
                            stmt_end = j
                            break
                    j += 1
                # Find the top-level `by` that separates aggregations from keys.
                by_pos, d3, k = -1, 0, i + 9
                while k < stmt_end:
                    if mask[k]:
                        ck = kql[k]
                        if ck in _OPEN:
                            d3 += 1
                        elif ck in _CLOSE:
                            d3 -= 1
                        elif d3 == 0 and lower.startswith("by", k) and _is_word(kql, k, k + 2):
                            by_pos = k
                            break
                    k += 1
                if by_pos != -1:
                    key_start = by_pos + 2
                    new_region, removed = _dedupe_key_region(
                        kql[key_start:stmt_end], mask, key_start)
                    if removed:
                        repls.append((key_start, stmt_end, new_region))
                        removed_all.extend(removed)
                i = stmt_end
                continue
        i += 1

    if not repls:
        return kql, []
    out = kql
    for s, e, txt in sorted(repls, key=lambda r: r[0], reverse=True):
        out = out[:s] + txt + out[e:]
    return out, removed_all


def rewrite(kql: str, tables: Optional[List[str]],
            catalog: Optional[dict] = None) -> dict:
    """Deterministically rewrite a Sentinel query for Advanced Hunting.

    Returns:
      convertedKql   - the rewritten query.
      diff           - [{kind, before, after, count, source, reason}].
      renamedTables  - {sentinelTable: ahTable} applied.
      flags          - [{kind, name, reason}] items needing review / blocking.
      tiers          - {table: tier}.
      overallTier    - worst tier across the query's tables.
      deterministic  - True iff every table is 1to1 and nothing was flagged.
    """
    cat = catalog or mapping_catalog.load_mapping_catalog()
    tbl_map = cat["tables"]
    tables = list(tables or [])

    # Column renames: global + per-table for the tables present.
    col_renames: Dict[str, str] = dict(cat["global"].get("columnRenames", {}))
    table_renames: Dict[str, str] = {}
    tiers: Dict[str, str] = {}
    flags: List[dict] = []
    global_drop_cols = set(cat["global"].get("dropColumns", []))
    drop_cols: set[str] = set()
    cast_cols: Dict[str, List[str]] = {}
    int_cols: Dict[str, List[str]] = {}
    removed_cols: Dict[str, List[str]] = {}

    for t in tables:
        entry = tbl_map.get(t)
        tier = entry["tier"] if entry else "unknown"
        tiers[t] = tier
        if not entry:
            flags.append({"kind": "unknown-table", "name": t,
                          "reason": "Table is not in the mapping catalog "
                                    "(custom/unsupported); cannot convert."})
            continue
        if tier == "blocked":
            flags.append({"kind": "blocked-table", "name": t,
                          "reason": entry.get("blockedReason",
                                              "No confirmed AH equivalent.")})
            continue
        if entry.get("applyGlobalDropColumns", True):
            drop_cols.update(global_drop_cols)
        col_renames.update(entry.get("columnRenames", {}))
        drop_cols.update(entry.get("dropColumns", []))
        ah = entry.get("ahTable")
        if ah and ah != t:
            table_renames[t] = ah
        if tier in ("renamed", "merged"):
            flags.append({"kind": "non-1to1-table", "name": t,
                          "reason": f"Tier '{tier}': {entry.get('notes', '')}".strip()})
        if entry.get("castDynamicColumns"):
            cast_cols[t] = list(entry["castDynamicColumns"])
        if entry.get("intColumns"):
            int_cols[t] = list(entry["intColumns"])
        if entry.get("removedColumns"):
            removed_cols[t] = list(entry["removedColumns"])

    # Apply table + column renames in one whole-identifier pass.
    rename_map = {**col_renames, **table_renames}
    converted, counts = _apply_renames(kql, rename_map)

    # Drop redundant duplicate group-by keys (AH rejects duplicate output columns).
    converted, dup_keys = _dedupe_summarize_keys(converted)

    # Wave-1 known column gotchas (docs/Sentinel-to-XDR-KQL-Migration-V2 1.md):
    # un-cast dynamic-as-string columns, quoted int-typed literals, removed columns.
    converted, cast_diffs = dynamic_casts.inject_dynamic_casts(converted, cast_cols)
    converted, int_diffs = dynamic_casts.unquote_int_literals(converted, int_cols)
    removed_flags = dynamic_casts.flag_removed_columns(converted, removed_cols)
    flags.extend(removed_flags)

    diff: List[dict] = []
    for src, cnt in counts.items():
        kind = "table-rename" if src in table_renames else "column-rename"
        reason = ("AH table name differs" if kind == "table-rename"
                  else "Column renamed in AH")
        diff.append({"kind": kind, "before": src, "after": rename_map[src],
                     "count": cnt, "source": "deterministic", "reason": reason})
    for key in dup_keys:
        diff.append({"kind": "dedupe-summarize-key", "before": key, "after": "(removed)",
                     "count": 1, "source": "deterministic",
                     "reason": "Duplicate summarize group-by key removed; "
                               "AH rejects duplicate output columns"})
    diff.extend(cast_diffs)
    diff.extend(int_diffs)

    # ASIM unifying-parser function calls (_Im_WebSession(...), _Im_NetworkSession(...),
    # etc.) don't resolve in AH; swap them for the AH-native ASim<Schema>Logs table,
    # inlining any named params we have a verified translation for.
    # [ASIM-FIX-TAG 2026-08-03] Rewrite disabled per ASIM_REWRITE_ENABLED (see top of
    # file) - left as an unrewritten flag instead, same as the "unknown param" path
    # asim_functions.py already produces, so it still routes to manual review rather
    # than silently passing through unconverted.
    if ASIM_REWRITE_ENABLED:
        asim_result = asim_functions.rewrite_im_calls(converted, cat)
        converted = asim_result["convertedKql"]
        diff.extend(asim_result["diff"])
        flags.extend(asim_result["flags"])
    else:
        asim_result = {"diff": [], "flags": asim_functions.flag_im_calls(converted)}
        flags.extend(asim_result["flags"])

    # [ASIM-FIX-TAG 2026-08-02] Per the spec (KQL-Conversion-Service-Spec.md, "Step 1 -
    # Resolve data sources"), an unresolvable ASIM unifying parser is allowed to be
    # recorded as `dataSourcesError`/null and routed to manual review rather than
    # guessed at. We instead resolve and convert these deterministically via the
    # verified asimFunctionRewrites catalog - a real table substitution the spec left
    # optional ("a future parser-expansion mapping", see spec §9 Open Questions). Every
    # such substitution must stay visible to reviewers, so record it separately from
    # `renamedTables` (which only covers ordinary 1:1/renamed LA->AH table maps) and
    # surface it distinctly in the dashboard rather than silently folding it in.
    renamed_asim_tables = {d["func"]: d["ahTable"] for d in asim_result["diff"]
                           if d["kind"] == "asim-function-rewrite"}

    diff.sort(key=lambda d: (d["kind"], d["before"]))

    # Flag references to LA-only columns that don't exist in AH (never delete).
    for col in sorted(_find_identifiers(kql, drop_cols)):
        flags.append({"kind": "la-only-column", "name": col,
                      "reason": "Log-Analytics-only column not present in AH; "
                                "query references it and needs manual handling."})

    overall = "1to1"
    if tables:
        overall = max((tiers[t] for t in tables), key=lambda x: _TIER_RANK.get(x, 2))
    else:
        overall = "unknown"
    # [ASIM-FIX 2026-08-02] "asim-function-unrewritten" added to the gate below -
    # previously an unrewritten _Im_<Schema>(...) call (unknown param, left as-is by
    # asim_functions.py) did not block `deterministic`, letting AH's silent-bind-to-
    # wrong-table behavior masquerade as a passing static bind. See batch_xdr.py's
    # matching [ASIM-FIX 2026-08-02] guard and mcp/tests/test_asim_functions.py.
    has_review_flag = any(f["kind"] in ("la-only-column", "removed-column",
                                        "asim-function-unrewritten") for f in flags)
    deterministic = bool(tables) and overall == "1to1" and not has_review_flag

    return {
        "convertedKql": converted,
        "diff": diff,
        "renamedTables": table_renames,
        "renamedAsimTables": renamed_asim_tables,
        "flags": flags,
        "tiers": tiers,
        "overallTier": overall,
        "deterministic": deterministic,
    }
