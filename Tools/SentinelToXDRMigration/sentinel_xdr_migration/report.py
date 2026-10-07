from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from .report_dashboard import STYLE, THEME_SCRIPT

REPORT_STYLE = STYLE + """
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 24px 0; }
.card { background: var(--cp-surface); border: 1px solid var(--cp-border); border-radius: 16px; padding: 16px; }
.card strong { display: block; font-size: 2rem; margin-top: 4px; }
.status { display: inline-block; border: 1px solid var(--cp-border); border-radius: .625rem; padding: 4px 8px; font-weight: 600; }
.converted { border-left: 4px solid var(--cp-success); }
.needsReview { border-left: 4px solid var(--cp-accent); }
.conflict { border-left: 4px solid var(--cp-danger); }
"""


def _messages(values: list[str], empty: str) -> str:
    if not values:
        return f'<span class="muted">{escape(empty)}</span>'
    return "<ul>" + "".join(f"<li>{escape(value)}</li>" for value in values) + "</ul>"


def render_transformation_report(summary: dict[str, Any]) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scope = summary.get("scope") or {}
    scope_notice = (
        "Rule-scoped conversion only: " + ", ".join(scope.get("ruleIds") or [])
        + ". Unselected drafts were not converted. Counts apply only to the selected rule; "
        "this is not full-solution conversion, structural validation, or packaging readiness."
        if scope.get("kind") == "rule"
        else "Full-solution conversion scope."
    )
    rows: list[str] = []
    for result in summary["results"]:
        status = str(result["status"])
        review_required = bool(result.get("reviewRequired"))
        display_name = str(result.get("displayName") or Path(result["source"]).stem)
        source_name = str(result.get("sourceRelativePath") or result["source"])
        output_name = str(result.get("outputRelativePath") or result["output"])
        warnings = list(result.get("warnings") or [])
        errors = list(result.get("errors") or [])
        informational = list(result.get("informational") or [])
        reviews = list(result.get("reviewReasons") or [])
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(display_name)}</strong><br><span class="muted">{escape(source_name)} -&gt; {escape(output_name)}</span></td>
              <td><span class="status {escape(status)}">{escape(status)}</span>
              {'<br><span class="muted">Review required</span>' if review_required else ''}</td>
              <td>{_messages(errors, "—")}</td>
              <td>{_messages(reviews, "—")}</td>
              <td>{_messages(warnings, "—")}</td>
              <td>{_messages(informational, "—")}</td>
            </tr>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sentinel to XDR transformation report</title>
  <script>{THEME_SCRIPT}</script>
  <style>{REPORT_STYLE}</style>
</head>
<body>
<main>
  <h1>Sentinel to XDR transformation report</h1>
  <div class="muted">{escape(str(summary["solution"]))} - Generated {generated_at}</div>
  <p>{escape(scope_notice)}</p>
  <section class="cards">
    <div class="card">Rules attempted<strong>{summary["total"]}</strong></div>
    <div class="card">Converted<strong>{summary["converted"]}</strong></div>
    <div class="card">Excluded<strong>{summary.get("excluded", 0)}</strong></div>
    <div class="card">Review required<strong>{summary.get("reviewRequired", summary["needsReview"])}</strong></div>
    <div class="card">Conflicts<strong>{summary["conflicts"]}</strong></div>
    <div class="card">Rules with information<strong>{sum(bool(result.get("informational")) for result in summary["results"])}</strong></div>
  </section>
  <p>Information is nonblocking conversion context, separate from warnings, human-review decisions, and errors. It never changes conversion status or readiness.</p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Rule</th><th>Status</th><th>Errors</th><th>Reviews</th><th>Warnings</th><th>Information — nonblocking</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</main>
</body>
</html>
"""


def write_transformation_report(summary: dict[str, Any], path: Path) -> None:
    path.write_text(render_transformation_report(summary), encoding="utf-8", newline="\n")


def render_runtime_validation_report(summary: dict[str, Any]) -> str:
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    rows: list[str] = []
    for result in summary["results"]:
        status = str(result["status"])
        error = str(result.get("error") or "")
        rows.append(
            f"""
            <tr>
              <td><strong>{escape(str(result["detection"]))}</strong></td>
              <td><span class="status {escape(status)}">{escape(status)}</span></td>
              <td>{result.get("rowCount", 0)}</td>
              <td>{result.get("schemaColumnCount", 0)}</td>
              <td>{escape(error) if error else '<span class="muted">None</span>'}</td>
            </tr>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(str(summary["platform"]))} runtime validation report</title>
  <script>{THEME_SCRIPT}</script>
  <style>{REPORT_STYLE}</style>
</head>
<body>
<main>
  <h1>{escape(str(summary["platform"]))} runtime validation</h1>
  <div class="muted">{escape(str(summary["solution"]))} - Provider: {escape(str(summary["provider"]))} - Generated {generated_at}</div>
  <section class="cards">
    <div class="card">Rules tested<strong>{summary["total"]}</strong></div>
    <div class="card">Passed<strong>{summary["valid"]}</strong></div>
    <div class="card">Failed<strong>{summary["invalid"]}</strong></div>
    <div class="card">Blocked<strong>{summary["blocked"]}</strong></div>
    <div class="card">Not run<strong>{summary.get("notRun", 0)}</strong></div>
  </section>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Detection</th><th>Status</th><th>Rows</th><th>Schema columns</th><th>Error</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</main>
</body>
</html>
"""


def write_runtime_validation_report(summary: dict[str, Any], path: Path) -> None:
    path.write_text(
        render_runtime_validation_report(summary), encoding="utf-8", newline="\n"
    )
