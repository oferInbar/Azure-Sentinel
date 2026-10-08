"""Offline presentation of recorded migration facts; never changes workflow gates."""

from __future__ import annotations

from collections import Counter
from difflib import unified_diff
from html import escape
import json
import math
import re
from typing import Any

from .report_review import BULK_SCRIPT, render_bulk_review, review_candidates


THEME_SCRIPT = """
  (() => {
    const param = new URLSearchParams(window.location.search).get("scoutTheme");
    const theme =
      param || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
  })();
"""

STYLE = """
:root {
  color-scheme: light;
  --cp-bg: #f7f4ef;
  --cp-bg-elevated: #fcfbf8;
  --cp-surface: #ffffff;
  --cp-surface-soft: #f5f5f5;
  --cp-border: #dedede;
  --cp-border-strong: #919191;
  --cp-text: #242424;
  --cp-text-muted: #5c5c5c;
  --cp-text-soft: #6f6f6f;
  --cp-accent: #b11f4b;
  --cp-accent-hover: #9a1a41;
  --cp-accent-soft: rgba(177, 31, 75, 0.08);
  --cp-accent-fg: #ffffff;
  --cp-success: #16a34a;
  --cp-danger: #dc2626;
  --cp-warning: #f59e0b;
  --cp-link: #0078d4;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.12);
  --cp-overlay: rgba(255, 255, 255, 0.8);
  --cp-panel: rgba(255, 255, 255, 0.86);
  --cp-panel-strong: rgba(255, 255, 255, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.55);
  --cp-highlight: rgba(177, 31, 75, 0.12);
}
html[data-theme="dark"] {
  color-scheme: dark;
  --cp-bg: #3d3b3a;
  --cp-bg-elevated: #343231;
  --cp-surface: #292929;
  --cp-surface-soft: #2e2e2e;
  --cp-border: #474747;
  --cp-border-strong: #5f5f5f;
  --cp-text: #dedede;
  --cp-text-muted: #919191;
  --cp-text-soft: #b0b0b0;
  --cp-accent: #fd8ea1;
  --cp-accent-hover: #fb7b91;
  --cp-accent-soft: rgba(253, 142, 161, 0.14);
  --cp-accent-fg: #1a1a1a;
  --cp-success: #4ade80;
  --cp-danger: #f87171;
  --cp-warning: #fbbf24;
  --cp-link: #4da6ff;
  --cp-shadow: 0 18px 48px rgba(0, 0, 0, 0.32);
  --cp-overlay: rgba(41, 41, 41, 0.88);
  --cp-panel: rgba(41, 41, 41, 0.72);
  --cp-panel-strong: rgba(41, 41, 41, 0.96);
  --cp-sheen: rgba(255, 255, 255, 0.04);
  --cp-highlight: rgba(253, 142, 161, 0.12);
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--cp-bg); color: var(--cp-text);
  font-family: "Segoe UI", Aptos, Calibri, -apple-system, BlinkMacSystemFont, sans-serif; }
main { max-width: 1560px; margin: auto; padding: 24px; }
h1 { margin: 8px 0; } h2 { font-size: 1.2rem; }
a { color: var(--cp-link); } .muted { color: var(--cp-text-muted); }
.panel { background: var(--cp-surface); border: 1px solid var(--cp-border);
  border-radius: 16px; padding: 20px; margin: 16px 0; }
.stages, .chips, .categories, .metrics { display: flex; flex-wrap: wrap; gap: 8px; }
.stages { list-style: none; padding: 0; }
.stage, .badge { border: 1px solid var(--cp-border); padding: 4px 8px; border-radius: .625rem; }
.badge { display: inline-block; margin: 4px 0; font-size: .85rem; }
.failed { border-left: 4px solid var(--cp-danger); }
.review, .unconfirmed, .blocked { border-left: 4px solid var(--cp-warning); }
.ready, .passed { border-left: 4px solid var(--cp-success); }
.finding-error { border-left: 4px solid var(--cp-danger); }
.finding-review { border-left: 4px solid var(--cp-accent); }
.finding-warning { border-left: 4px solid var(--cp-link); }
.finding-blocked { border-left: 4px solid var(--cp-warning); }
.finding-info { border-left: 4px solid var(--cp-border-strong); }
.metrics span { padding: 8px 12px; background: var(--cp-surface-soft); border-radius: .625rem; }
fieldset { border: 0; padding: 0; margin: 16px 0; }
legend { font-weight: 600; margin-bottom: 8px; }
label.chip { border: 1px solid var(--cp-border); padding: 8px 12px;
  border-radius: .625rem; cursor: pointer; background: var(--cp-surface); }
label.chip:has(input:checked) { border-color: var(--cp-accent); background: var(--cp-accent-soft); }
input { accent-color: var(--cp-accent); }
input[type=search] { display: block; margin-top: 8px; width: min(100%, 640px); }
input[type=search], button { font: inherit; padding: 8px 12px; border: 1px solid var(--cp-border-strong);
  border-radius: .625rem; background: var(--cp-surface); color: var(--cp-text); }
select { font: inherit; padding: 8px; max-width: 100%; background: var(--cp-surface); color: var(--cp-text);
  border: 1px solid var(--cp-border-strong); border-radius: .625rem; }
button:disabled { color: var(--cp-text-muted); cursor: not-allowed; }
.chart-layout { display: flex; flex-wrap: wrap; align-items: center; gap: 24px; }
.donut { width: 220px; max-width: 100%; height: 220px; }
.donut circle { fill: none; stroke-width: 5; }
.donut-track { stroke: var(--cp-border); }
.donut-green { stroke: var(--cp-success); }
.donut-yellow { stroke: var(--cp-warning); }
.donut-red { stroke: var(--cp-danger); }
.donut-gray { stroke: var(--cp-text-muted); }
.donut text { text-anchor: middle; fill: var(--cp-text); font-size: 3px; }
.donut .chart-total { font-size: 6px; font-weight: 600; }
.chart-legend { display: grid; gap: 8px; }
.chart-legend button { text-align: left; }
[data-chart-filter][aria-pressed=true] { outline: 2px solid var(--cp-accent); outline-offset: 2px; }
.swatch { display: inline-block; width: 12px; height: 12px; margin-right: 8px; border-radius: 50%; }
.swatch-green { background: var(--cp-success); }
.swatch-yellow { background: var(--cp-warning); }
.swatch-red { background: var(--cp-danger); }
.swatch-gray { background: var(--cp-text-muted); }
.findings-pie { width: 160px; height: 160px; max-width: 100%; }
.pie-error { fill: var(--cp-danger); }
.pie-attention { fill: var(--cp-warning); }
.pie-info { fill: var(--cp-link); }
.pie-empty { fill: var(--cp-border); }
.swatch-info { background: var(--cp-link); }
[data-findings-chart-filter][aria-pressed=true] { outline: 2px solid var(--cp-accent); outline-offset: 2px; }
button, summary { cursor: pointer; } button:hover { border-color: var(--cp-accent); }
:focus-visible { outline: 3px solid var(--cp-accent); outline-offset: 3px; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; background: var(--cp-surface); }
th, td { text-align: left; vertical-align: top; padding: 12px; border-bottom: 1px solid var(--cp-border); }
thead th { position: sticky; top: 0; background: var(--cp-bg-elevated); z-index: 1; }
th:first-child { min-width: 220px; } td { overflow-wrap: anywhere; }
tbody.rule > tr:first-child > th { font-weight: normal; width: 30%; }
.detail-cell { background: var(--cp-bg-elevated); }
summary { padding: 8px 0; font-weight: 600; }
pre, code { font-family: Consolas, "Courier New", Courier, monospace; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; max-height: 420px; overflow: auto;
  background: var(--cp-surface-soft); border: 1px solid var(--cp-border); padding: 12px; border-radius: .625rem; }
.query-pair { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.issue-list { padding-left: 24px; } .issue-list li { padding: 8px 0; }
[hidden] { display: none !important; }
@media(max-width: 760px) { main { padding: 12px; } .panel { padding: 12px; }
  .query-pair { grid-template-columns: 1fr; } }
"""

FILTER_SCRIPT = """
(() => {
  const form = document.getElementById("filters");
  const rows = [...document.querySelectorAll("tbody.rule")];
  const search = document.getElementById("search");
  const count = document.getElementById("result-count");
  const issueLabel = document.getElementById("issue-filter");
  let issue = "";
  let chart = "all";
  let findingChart = "all";
  function apply() {
    const status = form.querySelector('input[name="status"]:checked').value;
    const finding = form.querySelector('input[name="finding"]:checked').value;
    const categories = [...form.querySelectorAll('input[name="category"]:checked')].map(x => x.value);
    const text = search.value.trim().toLowerCase();
    let visible = 0;
    rows.forEach(row => {
      const matchesStatus = status === "all" ||
        (status === "attention" ? !["ready", "excluded"].includes(row.dataset.status) : row.dataset.status === status);
      const matchesCategory = !categories.length || categories.some(x => row.dataset.categories.split("|").includes(x));
      const matchesFinding = finding === "any" || row.dataset.findings.split("|").includes(finding);
      const kinds = row.dataset.findings.split("|");
      const matchesFindingChart = findingChart === "all" ||
        (findingChart === "attention" ? kinds.some(kind => ["warning", "review"].includes(kind)) : kinds.includes(findingChart));
      row.hidden = !(matchesStatus && matchesFinding && matchesCategory && row.dataset.search.includes(text) &&
        matchesFindingChart &&
        (chart === "all" || row.dataset.chart === chart) &&
        (!issue || row.dataset.issues.split("|").includes(issue)));
      if (!row.hidden) visible++;
    });
    count.textContent = `Showing ${visible} of ${rows.length} rules`;
    document.getElementById("empty").hidden = visible !== 0;
    issueLabel.textContent = issue ? `Filtering to shared issue ${issue.replace("issue-", "")}` : "";
    document.getElementById("clear-issue").hidden = !issue;
    document.querySelectorAll("[data-chart-filter]").forEach(control => control.setAttribute("aria-pressed", String(control.dataset.chartFilter === chart)));
    document.getElementById("chart-filter-label").textContent = chart === "all" ? "" :
      `Chart filter: ${document.querySelector('button[data-chart-filter="' + chart + '"]').dataset.chartLabel}`;
    document.querySelectorAll("[data-findings-chart-filter]").forEach(control => control.setAttribute("aria-pressed", String(control.dataset.findingsChartFilter === findingChart)));
    document.getElementById("finding-chart-filter-label").textContent = findingChart === "all" ? "" :
      `Findings chart filter: ${document.querySelector('button[data-findings-chart-filter="' + findingChart + '"]').dataset.findingLabel}`;
  }
  form.addEventListener("input", event => {
    if (event.target.name === "finding") form.querySelector('input[name="status"][value="all"]').checked = true;
    apply();
  });
  form.addEventListener("submit", event => event.preventDefault());
  document.getElementById("clear").addEventListener("click", () => {
    form.reset();
    form.querySelector('input[value="all"]').checked = true;
    issue = "";
    chart = "all";
    findingChart = "all";
    apply();
  });
  document.getElementById("clear-issue").addEventListener("click", () => { issue = ""; apply(); });
  document.querySelectorAll("[data-filter-issue]").forEach(button => button.addEventListener("click", () => {
    form.reset();
    form.querySelector('input[value="all"]').checked = true;
    issue = button.dataset.filterIssue;
    chart = "all";
    findingChart = "all";
    apply();
    document.getElementById("result-count").focus();
  }));
  document.querySelectorAll("[data-chart-filter]").forEach(control => {
    function select() {
      form.reset();
      form.querySelector('input[name="status"][value="all"]').checked = true;
      issue = "";
      chart = control.dataset.chartFilter;
      findingChart = "all";
      apply();
      document.getElementById("result-count").focus();
    }
    control.addEventListener("click", select);
    if (control.tagName.toLowerCase() === "circle") control.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
    });
  });
  document.querySelectorAll("[data-findings-chart-filter]").forEach(control => {
    function select() {
      form.reset();
      form.querySelector('input[name="status"][value="all"]').checked = true;
      issue = "";
      chart = "all";
      findingChart = control.dataset.findingsChartFilter;
      apply();
      document.getElementById("result-count").focus();
    }
    control.addEventListener("click", select);
    if (["path", "circle"].includes(control.tagName.toLowerCase())) control.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(); }
    });
  });
  document.querySelectorAll("[data-toggle-detail]").forEach(button => button.addEventListener("click", () => {
    const detail = document.getElementById(button.getAttribute("aria-controls"));
    detail.hidden = !detail.hidden;
    button.setAttribute("aria-expanded", String(!detail.hidden));
  }));
  apply();
})();
"""

STATUS_LABELS = {
    "attention": "Needs attention",
    "all": "All",
    "ready": "Ready for validation",
    "review": "Needs review",
    "failed": "Blocked / Failed",
    "notstarted": "Not started",
    "unconfirmed": "Readiness unconfirmed",
    "excluded": "Excluded",
}

STAGE_LABELS = {
    "discovery": "Discovery", "conversion": "Conversion", "validation": "Validation",
    "packaging": "Packaging", "deployment": "Deployment", "mockIngestion": "Mock ingestion",
    "alertParity": "Alert parity", "report": "Report",
}

FINDING_LABELS = {
    "error": ("Errors", "Error", "!"),
    "review": ("Reviews", "Review — decision required", "?"),
    "blocked": ("Blocked prerequisites", "Blocked — not an execution failure", "Ⅱ"),
    "warning": ("Warnings", "Warning — nonblocking", "i"),
    "info": ("Information", "Information — nonblocking", "ℹ"),
}


def _finding_badge(severity: str) -> str:
    _, label, icon = FINDING_LABELS[severity]
    return f'<span class="badge finding-{severity}"><span aria-hidden="true">{icon}</span> {label}</span>'


def _text(value: Any) -> str:
    return escape(str(value)) if value is not None else "Evidence unavailable"


def _status_label(value: Any) -> str:
    return {
        "notRequired": "Not required", "pending": "Not started",
        "not-run": "Not run (recorded)", "not-recorded": "Evidence unavailable",
        "needsReview": "Needs review", "not-generated": "Not generated",
    }.get(str(value), str(value).replace("-", " ").capitalize() if value else "Evidence unavailable")


def _category(message: str, stage: str = "") -> str:
    text = (stage + " " + message).lower()
    if any(word in text for word in ("runtime", "deployment", "parity", "authentication")):
        return "Execution"
    if any(word in text for word in ("tactic", "technique")):
        return "Tactics"
    if any(word in text for word in ("entity", "mapping", "account", "upn", "host.", "filehash")):
        return "Identity / entities"
    if any(word in text for word in ("timestamp", "timegenerated", "lookback", "queryperiod", "schedule")):
        return "Time / schedule"
    if any(word in text for word in ("query", "table", "union", "search", "kql")):
        return "Query compatibility"
    return "Other"


def _message_key(message: str, stage: str) -> str:
    if stage == "structural-validation" and message.startswith("conversion: "):
        return message[len("conversion: "):]
    return message


def _findings(rule: dict[str, Any]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    statuses = []
    for side_key, label in (("analyticRule", "Sentinel"), ("customDetection", "XDR")):
        side = rule.get(side_key) or {}
        prefix = "analytic-rule" if side_key == "analyticRule" else "custom-detection"
        for item in side.get("runtime") or []:
            statuses.append((f"{prefix}-runtime-validation", f"{label} runtime", item))
        statuses.append((f"{prefix}-deployment", f"{label} deployment", {"status": side.get("deploymentStatus")}))
    custom = rule["customDetection"]
    alert_statuses = [custom.get("alertStatus"), (rule.get("analyticRule") or {}).get("alertStatus")]
    statuses.extend([
        ("conversion", "Conversion", {"status": custom.get("conversionStatus")}),
        ("structural-validation", "Local structural check", {"status": custom.get("structuralStatus")}),
        ("query-result-parity", "Query parity", rule.get("queryParity") or {}),
        ("alert-parity", "Alert parity", {
            "status": "failed" if "failed" in alert_statuses else "blocked" if "blocked" in alert_statuses else custom.get("alertStatus"),
            "analyticRuleStatus": alert_statuses[1], "customDetectionStatus": alert_statuses[0],
        }),
    ])

    def diagnostic_severity(item: dict[str, Any]) -> str:
        matches = [
            value.get("status") for stage, _, value in statuses
            if stage == item.get("stage") and (
                not item.get("provider") or not value.get("provider") or item["provider"] == value["provider"]
            )
        ]
        return "blocked" if "blocked" in matches and not any(value in {"failed", "conflict"} for value in matches) else "error"

    items = [
        (diagnostic_severity(item), item.get("stage", "unknown"), str(item.get("message", "")), item)
        for item in rule.get("errors") or []
    ]
    for stage, label, value in statuses:
        status = value.get("status")
        if status not in {"failed", "blocked", "conflict"}:
            continue
        if any(
            raw.get("stage") == stage and (
                not value.get("provider") or not raw.get("provider") or raw["provider"] == value["provider"]
            )
            for raw in rule.get("errors") or []
        ):
            continue
        items.append(("blocked" if status == "blocked" else "error", stage,
                      f"{label}: {_status_label(status)}", value))
    items += [
        (
            "review",
            "conversion-review",
            str(message),
            {
                "message": message,
                "reviewScope": custom.get("reviewScope"),
                "reviewDecisions": [
                    decision for decision in custom.get("reviewDecisions") or []
                    if isinstance(decision, dict) and decision.get("reason") == message
                ],
            },
        )
        for message in rule["customDetection"].get("reviewReasons") or []
    ]
    if (custom.get("reviewRequired") or custom.get("conversionStatus") == "needsReview") and not custom.get("reviewReasons"):
        items.append(("review", "conversion-review", "Review required; detailed reason not recorded.",
                      {"reviewRequired": custom.get("reviewRequired"), "conversionStatus": custom.get("conversionStatus")}))
    items += [
        ("warning", "conversion-warning", str(message), {"message": message})
        for message in rule.get("warnings") or []
    ]
    items += [
        ("info", "conversion-information", str(message), {"message": message})
        for message in rule.get("informational") or []
    ]
    for side_key in ("analyticRule", "customDetection"):
        for runtime in (rule.get(side_key) or {}).get("runtime") or []:
            fallback = runtime.get("providerFallback")
            if fallback:
                items.append((
                    "info",
                    "runtime-provider-fallback",
                    "Triage MCP provider gap recorded; complete query family rerun through "
                    f"{fallback.get('fallbackProvider')}: {fallback.get('reason')}",
                    {"provider": runtime.get("provider"), "providerFallback": fallback},
                ))
    for severity, stage, message, raw in items:
        key = _message_key(message, stage)
        # Only the inherited conversion/structural pair shares an error identity.
        scope = "conversion" if stage in {"conversion", "structural-validation"} else stage
        identity = (
            f"{scope}:{key}" if severity in {"error", "blocked"}
            else f"information:{key}" if severity == "info" else f"advisory:{key}"
        )
        if identity not in grouped:
            grouped[identity] = {
                "message": key, "severity": severity, "stages": [],
                "category": _category(key, stage), "evidence": [],
            }
        finding = grouped[identity]
        if stage not in finding["stages"]:
            finding["stages"].append(stage)
        finding["evidence"].append({"stage": stage, **raw})
    return sorted(grouped.values(), key=lambda finding: list(FINDING_LABELS).index(finding["severity"]))


def _rule_status(rule: dict[str, Any], workflow: dict[str, Any]) -> str:
    custom = rule["customDetection"]
    sides = [rule.get("analyticRule") or {}, custom]
    result_statuses = [
        runtime.get("status")
        for side in sides for runtime in side.get("runtime") or []
    ] + [
        side.get(field) for side in sides for field in ("alertStatus", "deploymentStatus")
    ] + [
        (rule.get("queryParity") or {}).get("status"),
        custom.get("structuralStatus"),
        custom.get("conversionStatus"),
    ]
    if rule.get("errors") or any(value in {"failed", "blocked", "conflict"} for value in result_statuses):
        return "failed"
    if custom.get("reviewRequired") or custom.get("reviewReasons") or custom.get("conversionStatus") == "needsReview":
        return "review"
    if custom.get("conversionStatus") == "excluded":
        return "excluded"
    if custom.get("conversionStatus") in {None, "not-run", "pending"}:
        return "notstarted"
    conversion = (workflow.get("stages") or {}).get("conversion") or {}
    if custom.get("conversionStatus") == "converted" and custom.get("structuralStatus") == "passed" and conversion.get("status") == "passed":
        return "ready"
    return "unconfirmed"


CHART_LABELS = {
    "green": "Automated checks passed",
    "yellow": "Warnings or review required",
    "red": "Errors",
    "gray": "Readiness unconfirmed",
}


def _chart_bucket(rule: dict[str, Any]) -> str:
    kinds = {finding["severity"] for finding in _findings(rule)}
    if "error" in kinds:
        return "red"
    if kinds.intersection({"review", "warning"}):
        return "yellow"
    custom = rule["customDetection"]
    if "blocked" not in kinds and custom.get("conversionStatus") == "converted" and custom.get("structuralStatus") == "passed":
        return "green"
    return "gray"


def _chart_html(rules: list[dict[str, Any]]) -> str:
    counts = Counter(_chart_bucket(rule) for rule in rules)
    total = len(rules)
    offset = 0.0
    arcs, legend = [], []
    for color, label in CHART_LABELS.items():
        count = counts[color]
        percentage = count * 100 / total if total else 0
        text = f"{label}: {count} rules ({percentage:.1f}%)"
        if count:
            arcs.append(
                f'<circle class="donut-{color}" cx="21" cy="21" r="15.9155" pathLength="100" '
                f'stroke-dasharray="{percentage:.6f} {100-percentage:.6f}" stroke-dashoffset="{-offset:.6f}" '
                f'transform="rotate(-90 21 21)" tabindex="0" role="button" aria-pressed="false" '
                f'aria-label="{text}" data-chart-filter="{color}"><title>{text}</title></circle>'
            )
        offset += percentage
        legend.append(
            f'<button type="button" data-chart-filter="{color}" data-chart-label="{label}" aria-pressed="false">'
            f'<span class="swatch swatch-{color}" aria-hidden="true"></span>{text}</button>'
        )
    return (
        '<section class="panel" aria-labelledby="chart-heading"><h2 id="chart-heading">Automated check overview — not deployment readiness</h2>'
        '<div class="chart-layout"><svg class="donut" viewBox="0 0 42 42" role="group" aria-label="Rule counts by automated-check outcome">'
        '<circle class="donut-track" cx="21" cy="21" r="15.9155"></circle>'
        + "".join(arcs) + f'<text class="chart-total" x="21" y="21">{total}</text><text x="21" y="26">rules</text></svg>'
        '<div class="chart-legend">' + "".join(legend)
        + '<button type="button" data-chart-filter="all" aria-pressed="true">Show all chart groups</button></div></div>'
        '<p>Each rule is counted once: errors take priority, then warnings/reviews, then passed automated conversion '
        'and local structural checks; insufficient evidence or a remaining per-rule prerequisite block is gray. '
        'Information alone is nonblocking and belongs in green when both automated checks passed. Missing results are never green.</p>'
        '<p class="muted">Green is not semantic approval or deployment readiness. A green rule can still have '
        'Readiness unconfirmed in the status filter while run-level conversion review remains incomplete. '
        'Chart selections reset other filters; further filters narrow the selected group.</p></section>'
    )


def _findings_chart_html(rules: list[dict[str, Any]]) -> str:
    counts = Counter(finding["severity"] for rule in rules for finding in _findings(rule))
    buckets = [
        ("error", "Errors", counts["error"], "red"),
        ("attention", "Warnings / reviews", counts["warning"] + counts["review"], "yellow"),
        ("info", "Informational", counts["info"], "info"),
    ]
    total = sum(count for _, _, count, _ in buckets)
    passed_rules = sum(_chart_bucket(rule) == "green" for rule in rules)
    angle = -math.pi / 2
    segments, legend = [], []
    for key, label, count, swatch in buckets:
        proportion = count / total if total else 0
        text = f"{label}: {count} findings ({proportion * 100:.1f}%)"
        attributes = (
            f'class="pie-{key}" tabindex="0" role="button" aria-pressed="false" '
            f'aria-label="{text}" data-findings-chart-filter="{key}"'
        )
        if count == total and total:
            segments.append(f'<circle cx="21" cy="21" r="18" {attributes}><title>{text}</title></circle>')
        elif count:
            end = angle + proportion * math.tau
            start_x, start_y = 21 + 18 * math.cos(angle), 21 + 18 * math.sin(angle)
            end_x, end_y = 21 + 18 * math.cos(end), 21 + 18 * math.sin(end)
            path = f"M21 21 L{start_x:.6f} {start_y:.6f} A18 18 0 {int(proportion > .5)} 1 {end_x:.6f} {end_y:.6f} Z"
            segments.append(f'<path d="{path}" {attributes}><title>{text}</title></path>')
        angle += proportion * math.tau
        legend.append(
            f'<button type="button" data-findings-chart-filter="{key}" data-finding-label="{label}" aria-pressed="false">'
            f'<span class="swatch swatch-{swatch}" aria-hidden="true"></span>{text}</button>'
        )
    if not total:
        segments.append('<circle class="pie-empty" cx="21" cy="21" r="18"><title>No charted findings</title></circle>')
    return (
        '<section class="panel" aria-labelledby="findings-chart-heading">'
        f'<h2 id="findings-chart-heading">High-level findings — {total} distinct findings</h2>'
        '<div class="chart-layout"><svg class="findings-pie" viewBox="0 0 42 42" role="group" aria-label="Findings by type">'
        + "".join(segments) + '</svg><div class="chart-legend">' + "".join(legend)
        + '<button type="button" data-findings-chart-filter="all" aria-pressed="true">Show all finding types</button></div>'
        f'<div class="badge ready"><strong>{passed_rules} rules</strong> passed automated checks with no actionable findings'
        '<br><span class="muted">Separate rule metric; not a pie slice. Informational notes are allowed.</span></div></div>'
        '<p class="muted">Pie counts are deduplicated per-rule findings, not unique rules; one rule may contribute several. '
        f'Yellow combines {counts["warning"]} warnings and {counts["review"]} reviews. '
        f'Blocked prerequisite findings ({counts["blocked"]}) are tracked separately, not counted as errors or included in this pie. '
        'Select a slice or legend to show matching rules; the rule-list count may differ from the finding count.</p></section>'
    )


def _next_action(status: str, findings: list[dict[str, Any]]) -> str:
    if status == "failed":
        return "Inspect failed or blocked check evidence; resolve its cause before retrying."
    if status == "notstarted":
        return "Start conversion after the run prerequisites are satisfied."
    if status == "unconfirmed":
        return "See the run-level conversion review caution; no per-rule review decision is inferred."
    if status == "ready":
        return "Proceed to the workflow validation stage; deployment is not approved."
    if status == "excluded":
        return "Inspect the recorded exclusion before changing scope."
    categories = {item["category"] for item in findings if item["severity"] in {"error", "review", "blocked"}}
    if "Tactics" in categories:
        return "Review invalid or incompatible classification metadata. Authoring preserves all source tactics; regenerate historical single-tactic drafts after review."
    if "Identity / entities" in categories:
        return "Confirm the output identity mapping against source evidence."
    return "Review the recorded reasons and resolve the rule-specific decision."


def _is_tactic_review(finding: dict[str, Any]) -> bool:
    return finding["severity"] == "review" and "one tactic" in finding["message"].lower()


def _tactic_guide() -> str:
    return (
        '<details id="tactic-selection-guide-panel"><summary>Preserve source tactics; review historical single-tactic findings</summary>'
        '<section id="tactic-selection-guide" aria-label="Source tactic preservation guidance" tabindex="-1">'
        '<p><strong>Historical finding:</strong> authoring now preserves all source tactics in source order, '
        'with documented compatible techniques. Multiple tactics alone no longer require review. '
        'Regenerate older drafts explicitly; this report does not clear historical findings.</p>'
        '<p>V3.1 ARM packaging carries only the first tactic and its compatible techniques, without modifying YAML. '
        'This classification loss is not validated parity. Direct Graph deployment remains <strong>one tactic, '
        'with multiple compatible techniques and subtechniques under it</strong> — not one technique only.</p>'
        '<p>Do not pair the source lists by position or copy every technique into every tactic. '
        'Legacy overrides replace techniques only for their named source tactic; they cannot narrow or reorder the source tactics. '
        'Unknown or incompatible classifications still require correction.</p>'
        '<p><strong>Verified scope (2026-10-07):</strong> an isolated Microsoft Graph beta create request with '
        'multiple tactics returned HTTP 400: <q>Multiple MITRE tactics are not supported. Specify a single tactic..</q> '
        'The Defender UI was confirmed to allow one tactic with multiple techniques; a read-back of a UI-created '
        'rule also confirmed the nested technique/subtechnique shape. This is not a claim that the multi-tactic '
        'request succeeded, that ARM was tested, or that every future API version has the same restriction.</p>'
        '<p>The public <a href="https://learn.microsoft.com/en-us/graph/api/resources/security-alerttemplate?view=graph-rest-beta" '
        'rel="noreferrer">Graph beta alertTemplate reference</a> describes <code>tactics</code> as a collection. '
        'A collection-shaped property alone does not establish acceptance of multiple tactics. '
        'The <a href="https://learn.microsoft.com/en-us/graph/api/resources/security-mitretactic?view=graph-rest-beta" '
        'rel="noreferrer">mitreTactic reference</a> documents the techniques collection within a tactic.</p>'
        '<p>The converter preserves the original classification in '
        '<code>contentProvenance.conversion.originalTactics</code> and <code>originalTechniques</code>. '
        'Each affected rule below shows source lists, preserved provenance, the current draft, and a rule-specific '
        '<code>ruleOverrides</code> example. Missing metadata is reported rather than reconstructed. '
        'No selection is automatically approved, and this report changes no query, configuration, or workflow gate.</p></section></details>'
    )


def _tactic_details(rule: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    if not any(_is_tactic_review(finding) for finding in findings):
        return ""
    classification = rule.get("attackClassification") or {}
    sections = []
    for label, key in (
        ("Sentinel source tactics (independent list)", "sourceTactics"),
        ("Sentinel source techniques (independent list)", "sourceTechniques"),
        ("Original tactics preserved in draft provenance", "originalTactics"),
        ("Original techniques preserved in draft provenance", "originalTechniques"),
        ("Current draft tactics, techniques and subtechniques (exact recorded shape)", "draftTactics"),
    ):
        value = classification.get(key)
        text = json.dumps(value, indent=2, ensure_ascii=False) if value is not None else "Classification metadata not recorded."
        sections.append(f"<h5>{label}</h5><pre>{escape(text)}</pre>")
    original = classification.get("originalTactics")
    draft = classification.get("draftTactics")
    fallback = (
        isinstance(original, list) and len(original) > 1
        and isinstance(draft, list) and len(draft) == 1 and isinstance(draft[0], dict)
        and draft[0].get("tactic") == original[0] and not draft[0].get("techniques")
    )
    rule_id = (rule.get("analyticRule") or {}).get("id")
    example = {"ruleOverrides": {str(rule_id or "<source-rule-id>"): {
        "tactic": "<existing source tactic whose techniques need correction>",
        "techniques": ["<compatible technique ID>", "<additional compatible technique or subtechnique ID, if applicable>"],
    }}}
    return (
        '<section class="tactic-review"><h4>Historical tactic finding and retained classification</h4>'
        '<p><a href="#tactic-selection-guide">Authored YAML preserves all source tactics; deployment contracts differ.</a></p>'
        '<p>Source lists are independent; their positions do not establish tactic/technique pairings. '
        'Source metadata reflects the current file; provenance records the original conversion classification.</p>'
        + "".join(sections)
        + (
            '<p><strong>Unapproved fallback shape:</strong> this draft retains the first original tactic '
            f'({_text(original[0])}) with techniques omitted. It matches the converter fallback for an unresolved '
            'multi-tactic source; it is not an approved classification. Explicitly regenerate to preserve all source tactics '
            'and their documented compatible techniques/subtechniques.</p>' if fallback else
            '<p>The draft shape is not treated as proof that a selection was approved. Resolve the recorded review reason explicitly.</p>'
        )
        + '<h5>Rule-specific override example — illustrative, not ready to apply</h5>'
        f'<pre>{escape(json.dumps(example, indent=2, ensure_ascii=False))}</pre>'
        '<p>Replace every placeholder with reviewed values and remove unused optional entries. '
        'Use technique IDs, including dotted subtechnique IDs where appropriate, in the existing '
        '<code>techniques</code> list. Merge this rule entry into the existing migration configuration; '
        'do not replace other rules. No tactic or technique is selected by this example. '
        'An override is optional for technique corrections, not required merely for multiple tactics. '
        'It does not remove or reorder source tactics. Subsequent workflow checks remain required.</p></section>'
    )


def _query_html(rule: dict[str, Any]) -> str:
    queries = rule.get("queries") or {}
    source, converted = queries.get("source"), queries.get("converted")
    if source is None and converted is None:
        return ""
    pair = (
        '<div class="query-pair">'
        f'<section><h4>Source Sentinel KQL</h4><pre>{_text(source)}</pre></section>'
        f'<section><h4>Converted XDR KQL</h4><pre>{_text(converted)}</pre></section></div>'
    )
    if source is None or converted is None:
        diff = "<p>Comparison unavailable: one query was not recorded.</p>"
    elif source == converted:
        diff = "<p>Query unchanged.</p>"
    else:
        lines = unified_diff(
            str(source).splitlines(), str(converted).splitlines(),
            fromfile="Source Sentinel", tofile="Converted XDR", lineterm="",
        )
        diff = "<h4>Unified text diff</h4><pre>" + escape("\n".join(lines)) + "</pre>"
    return (
        '<details><summary>Source / converted queries</summary>'
        '<p class="muted">Current file snapshot at report generation; textual comparison is not proof of semantic equivalence.</p>'
        + pair + diff + "</details>"
    )


def _result_html(rule: dict[str, Any]) -> str:
    lines = []
    custom = rule["customDetection"]
    lines.append(f"<li>Conversion: {_text(_status_label(custom.get('conversionStatus')))}; "
                 f"local structural checks: {_text(_status_label(custom.get('structuralStatus')))}</li>")
    for name, side in (("Sentinel", rule.get("analyticRule") or {}), ("XDR", custom)):
        for runtime in side.get("runtime") or []:
            count = runtime.get("rowCount")
            measurement = f"{_text(count)} rows" if count is not None else "Row count unavailable"
            lines.append(
                f"<li>{name} runtime — {_text(runtime.get('provider'))}: "
                f"{_text(_status_label(runtime.get('status')))} · {measurement}</li>"
            )
        for field, label in (("deploymentStatus", "deployment"), ("alertStatus", "alerts")):
            value = side.get(field)
            if value not in {None, "not-run", "not-recorded"}:
                lines.append(f"<li>{name} {label}: {_text(_status_label(value))}</li>")
    parity = rule.get("queryParity") or {}
    if parity.get("status") not in {None, "not-run", "not-recorded"}:
        lines.append(f"<li>Query parity: {_text(_status_label(parity['status']))}")
        for field, label in (("analyticRuleRows", "Sentinel rows"), ("customDetectionRows", "XDR rows"), ("matchKey", "Match key")):
            if parity.get(field) is not None:
                lines.append(f" · {label}: {_text(parity[field])}")
        lines.append("</li>")
    return "<h4>Recorded checks</h4><ul>" + "".join(lines) + "</ul>"


def _run_html(report: dict[str, Any]) -> str:
    workflow = report.get("workflow") or {}
    stages = workflow.get("stages") or {}
    profile = workflow.get("profile")
    stage_html, evidence = [], []
    for name, stage in stages.items():
        label = STAGE_LABELS.get(name, name)
        status = stage.get("status")
        display_status = (
            "Pending" if status == "pending" and stage.get("attempts") != 0
            else _status_label(status)
        )
        stage_html.append(f'<li class="stage {_text(status)}">{_text(label)}: {_text(display_status)}</li>')
        if stage.get("message") or stage.get("evidence"):
            evidence.append(
                f"<details><summary>{_text(label)} — recorded context</summary>"
                f"<p>{_text(stage['message']) if stage.get('message') else ''}</p>"
                + "<ul>" + "".join(f"<li>{_text(item)}</li>" for item in stage.get("evidence") or []) + "</ul></details>"
            )
    if not stages:
        stage_html.append("<li>Workflow stage evidence unavailable.</li>")
    runtime_rules = sum(
        bool(rule.get("analyticRule", {}).get("runtime") or rule["customDetection"].get("runtime"))
        for rule in report["rules"]
    )
    workspace = "Configured in run context" if workflow.get("workspaceConfigured") else "Not recorded in run context"
    return (
        '<section class="panel" aria-labelledby="run-heading"><h2 id="run-heading">Run context</h2>'
        f"<p><strong>{_text(str(profile).capitalize() if profile else 'Profile unavailable')}</strong>"
        f" · Run {_text(workflow.get('runId'))} · {_text(_status_label(workflow.get('status')))}</p>"
        '<ol class="stages">' + "".join(stage_html) + "</ol>"
        f"<p>Workspace: {workspace}. Runtime evidence available for {runtime_rules} of {len(report['rules'])} rules.</p>"
        "<p class=\"muted\">Shared stage status does not override individual results. Missing evidence is not proof "
        "a check was skipped. Optional stages are marked Not required only when recorded by the workflow.</p>"
        "<details><summary>Run messages, environment reasons and historical evidence</summary>"
        "<p class=\"muted\">Recorded text may contain historical counts; current artifact counts appear below.</p>"
        + "".join(evidence) + "</details></section>"
    )


def render_dashboard(report: dict[str, Any]) -> str:
    workflow = report.get("workflow") or {}
    candidates = review_candidates(report)
    candidates_by_index = {candidate["index"]: candidate for candidate in candidates}
    prepared = []
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for index, rule in enumerate(report["rules"]):
        findings = _findings(rule)
        status = _rule_status(rule, workflow)
        for finding in findings:
            message = re.sub(
                r"ruleOverrides\.[0-9a-fA-F-]{36}\.", "ruleOverrides.<rule-id>.", finding["message"]
            )
            key = (finding["severity"], message)
            group = groups.setdefault(key, {"id": f"issue-{len(groups) + 1}", "message": message,
                                            "severity": finding["severity"], "rules": set()})
            group["rules"].add(index)
            finding["group"] = group
        prepared.append((rule, status, findings))
    counts = Counter(status for _, status, _ in prepared)
    counts["all"] = len(prepared)
    counts["attention"] = sum(status not in {"ready", "excluded"} for _, status, _ in prepared)
    finding_counts = Counter(finding["severity"] for _, _, findings in prepared for finding in findings)
    affected_counts = Counter(kind for _, _, findings in prepared for kind in {finding["severity"] for finding in findings})
    categories = sorted({finding["category"] for _, _, findings in prepared for finding in findings})
    chips = "".join(
        f'<label class="chip"><input type="radio" name="status" value="{key}"'
        f'{" checked" if key == "attention" else ""}> {label} ({counts[key]})</label>'
        for key, label in STATUS_LABELS.items() if key != "excluded" or counts[key]
    )
    category_html = "".join(
        f'<label class="chip"><input type="checkbox" name="category" value="{_text(category)}"> {_text(category)}</label>'
        for category in categories
    )
    finding_chips = (
        '<label class="chip"><input type="radio" name="finding" value="any" checked> Any finding</label>'
        + "".join(
            f'<label class="chip"><input type="radio" name="finding" value="{kind}"> {labels[0]} ({affected_counts[kind]} rules)</label>'
            for kind, labels in FINDING_LABELS.items()
        )
    )
    shared_groups = sorted(
        (group for group in groups.values() if len(group["rules"]) > 1),
        key=lambda group: (list(FINDING_LABELS).index(group["severity"]), -len(group["rules"])),
    )
    has_tactic_review = any(_is_tactic_review(finding) for _, _, findings in prepared for finding in findings)
    shared = ""
    for kind, labels in FINDING_LABELS.items():
        section = "".join(
            f'<li id="{group["id"]}">{_finding_badge(kind)} — '
            + ('<a href="#tactic-selection-guide">Historical single-tactic finding; preserve source tactics</a> '
               if _is_tactic_review(group) else _text(group["message"]) + " ")
            + f'<button type="button" data-filter-issue="{group["id"]}">Show {len(group["rules"])} affected rules'
            f'<span class="muted"> · Issue {group["id"].split("-")[1]}</span></button></li>'
            for group in shared_groups if group["severity"] == kind
        )
        if section:
            shared += f'<section data-finding-group="{kind}"><h3>{labels[0]}</h3><ul class="issue-list">{section}</ul></section>'
    rows = []
    order = {"failed": 0, "review": 1, "unconfirmed": 2, "notstarted": 3, "ready": 4, "excluded": 5}
    for index, (rule, status, findings) in sorted(enumerate(prepared), key=lambda item: (order[item[1][1]], str(item[1][0]["name"]).casefold())):
        reasons, advisories, information = [], [], []
        evidence: dict[str, list[str]] = {kind: [] for kind in FINDING_LABELS}
        for finding in findings:
            group = finding["group"]
            if _is_tactic_review(finding):
                reason = '<a href="#tactic-selection-guide">Historical single-tactic finding; preserve source tactics</a>'
            elif len(group["rules"]) > 1:
                reason = f'<a href="#{group["id"]}">{_text(finding["category"])} · Issue {group["id"].split("-")[1]}</a>'
            else:
                reason = _text(finding["message"])
            kind = finding["severity"]
            (advisories if kind == "warning" else information if kind == "info" else reasons).append(
                f"<li>{_finding_badge(kind)} {reason}</li>"
            )
            evidence[kind].append(
                f"<details><summary>{_finding_badge(kind)} — {_text(finding['message'])}</summary>"
                f"<p>Observed in: {_text(', '.join(finding['stages']))}</p>"
                f"<pre>{escape(json.dumps(finding['evidence'], indent=2, ensure_ascii=False))}</pre></details>"
            )
        if not reasons:
            reasons.append("<li>" + {
                "unconfirmed": "Automated conversion passed; semantic review completion is unconfirmed.",
                "ready": "Recorded conversion stage and local checks passed.",
                "notstarted": "No conversion result recorded.",
                "review": "Review required; no detailed reason recorded.",
                "failed": "A recorded check failed or is blocked; see evidence.",
                "excluded": "Excluded from conversion.",
            }[status] + "</li>")
        search = " ".join(
            str(value or "") for value in [
                rule["name"], rule.get("sourceFile"), rule.get("outputFile"),
                rule.get("analyticRule", {}).get("id"), rule["customDetection"].get("id"),
                *(finding["message"] for finding in findings),
            ]
        ).lower()
        detail_id = f"rule-detail-{index}"
        recommendation = rule.get("entityRecommendation")
        advisory_html = (
            f'<details class="advisories"><summary>Warnings ({len(advisories)}) — nonblocking advisories</summary>'
            f'<ul class="issue-list">{"".join(advisories)}</ul></details>' if advisories else ""
        )
        if information:
            advisory_html += (
                f'<details class="information"><summary>Information ({len(information)}) — nonblocking notes</summary>'
                f'<ul class="issue-list">{"".join(information)}</ul></details>'
            )
        selection_html = ""
        candidate = candidates_by_index.get(index)
        if candidate:
            selection_html = (
                '<br><label>'
                f'<input type="checkbox" class="review-select" data-review-id="{_text(candidate["id"])}" '
                f'{"disabled " if not candidate["eligible"] else ""}'
                f'title="{_text(candidate["reason"])}"> Select for reviewed override</label>'
            )
            if not candidate["eligible"]:
                selection_html += f'<p class="muted">{_text(candidate["reason"])}</p>'
        evidence_html = "".join(
            f'<section data-evidence-kind="{kind}"><h4>{FINDING_LABELS[kind][0]}</h4>{"".join(values)}</section>'
            for kind, values in evidence.items() if values
        )
        rows.append(
            f'<tbody class="rule" data-status="{status}" data-chart="{_chart_bucket(rule)}" data-search="{_text(search)}" '
            f'data-categories="{_text("|".join(sorted({finding["category"] for finding in findings})))}" '
            f'data-findings="{_text("|".join(sorted({finding["severity"] for finding in findings})))}" '
            f'data-issues="{_text("|".join(finding["group"]["id"] for finding in findings))}">'
            f'<tr><th scope="row"><strong>{_text(rule["name"])}</strong><br>'
            f'<span class="badge {status}">{STATUS_LABELS[status]}</span>{selection_html}</th>'
            f'<td><ul class="issue-list">{"".join(reasons)}</ul>{advisory_html}</td>'
            f'<td>{_text(_next_action(status, findings))}</td>'
            f'<td><button type="button" data-toggle-detail aria-expanded="false" aria-controls="{detail_id}"'
            f' aria-label="Details for {_text(rule["name"])}">Details</button></td></tr>'
            f'<tr id="{detail_id}" hidden><td colspan="4" class="detail-cell">'
            f'<p>Source: <code>{_text(rule.get("sourceFile"))}</code><br>'
            f'Output: <code>{_text(rule.get("outputFile"))}</code><br>'
            f'Sentinel ID: <code>{_text(rule.get("analyticRule", {}).get("id"))}</code> · '
            f'XDR ID: <code>{_text(rule["customDetection"].get("id"))}</code></p>'
            + (f"<p><strong>Entity recommendation:</strong> {_text(recommendation)}</p>" if recommendation else "")
            + _result_html(rule)
            + _tactic_details(rule, findings)
            + "<h4>Findings and original evidence</h4>"
            + (evidence_html if evidence_html else "<p>No rule-level findings recorded.</p>")
            + _query_html(rule) + "</td></tr></tbody>"
        )
    summary = report.get("summary") or {}
    scope = summary.get("conversionScope") or {}
    scope_notice = (
        '<section class="panel"><h2>Rule-scoped conversion only</h2>'
        f'<p>Selected source ID: {_text(", ".join(scope.get("ruleIds") or []))}. '
        'Unselected drafts were not converted in this attempt. Local structural passes '
        'do not establish full-solution conversion or packaging readiness.</p></section>'
        if scope.get("kind") == "rule" else ""
    )
    structural = sum(rule["customDetection"].get("structuralStatus") == "passed" for rule, _, _ in prepared)
    distinct_errors = sum(finding["severity"] == "error" for _, _, findings in prepared for finding in findings)
    occurrences = sum(
        len(finding["evidence"]) for _, _, findings in prepared
        for finding in findings if finding["severity"] == "error"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>{_text(report["solution"])} migration report</title>'
        f"<script>{THEME_SCRIPT}</script><style>{STYLE}</style></head><body><main>"
        f'<h1>{_text(report["solution"])} migration report</h1>'
        f'<p class="muted">Generated {_text(report.get("generatedAt"))} · Offline report · No environment writes</p>'
        + scope_notice
        + _findings_chart_html(report["rules"])
        + _run_html(report)
        + '<section class="panel" aria-labelledby="overview"><h2 id="overview">Current artifact overview</h2>'
        f'<div class="metrics"><span>{len(prepared)} rules</span><span>{_text(summary.get("converted"))} automated conversions</span>'
        f'<span>{_text(summary.get("needsReview"))} converter review flags</span><span>{structural} local structural passes</span>'
        f'<span>{distinct_errors} distinct rule errors · {occurrences} diagnostic occurrences</span></div>'
        '<h3>Finding types — separate from readiness</h3><div class="metrics">'
        + "".join(
            f'<span>{_finding_badge(kind)} <strong>{finding_counts[kind]}</strong> findings across {affected_counts[kind]} rules</span>'
            for kind in FINDING_LABELS
        )
        + '</div><p>Errors are failed checks/executions or recorded hard errors. Reviews are explicit unresolved human decisions. '
        'Warnings are nonblocking advisories: a time/schedule warning is not automatically a review or failure. '
        'Information records explicit backend informational notes; it is not a warning and does not by itself require attention. '
        'Blocked prerequisites are tracked separately from execution failures. Counts are deduplicated per rule; types may overlap.</p>'
        '<p>Ready for validation means automated checks and the recorded conversion stage passed. '
        'It does not mean deployment approval or proven semantic equivalence. When conversion review is incomplete, '
        'automated successes remain <strong>Readiness unconfirmed</strong>. '
        '<strong>Run-level caution:</strong> any historical semantic findings without structured rule mappings remain a run-level caution; '
        'they do not create per-rule Needs review flags. Warnings do not change readiness.</p></section>'
        + _chart_html(report["rules"])
        + ('<section class="panel"><details id="shared-findings"><summary>Shared findings — '
           f'{len(shared_groups)} repeated patterns</summary><p class="muted">Each explanation appears once here. '
           'Counts are affected rules, not diagnostic occurrences. Original per-rule evidence is preserved in Details.</p>'
           + (_tactic_guide() if has_tactic_review else "")
           + f'{shared}</details></section>' if shared or has_tactic_review else "")
        + render_bulk_review(report, candidates)
        + '<section class="panel"><h2>Rules</h2><form id="filters">'
        '<fieldset><legend>Status — select one; counts cover the entire run</legend><div class="chips">'
        + chips + '</div></fieldset><fieldset><legend>Finding type — counts are affected rules</legend><div class="chips">'
        + finding_chips + '</div><p class="muted">Choosing a finding type shows all statuses; refine status afterward. '
        'Warnings remain advisories even on a ready rule.</p></fieldset><label for="search">Search rule name, path, ID or finding</label>'
        '<input type="search" id="search" name="search" placeholder="Search this run">'
        '<fieldset><legend>Issue categories — any selected category</legend><div class="categories">'
        + category_html + '</div></fieldset><p class="muted">Status, search and categories are combined. '
        'Multiple categories match any selected category.</p>'
        '<button type="button" id="clear">Clear filters / show all</button></form>'
        '<p><span id="issue-filter"></span> <button type="button" id="clear-issue" hidden>Clear issue filter</button></p>'
        '<p id="chart-filter-label" role="status" aria-live="polite"></p>'
        '<p id="finding-chart-filter-label" role="status" aria-live="polite"></p>'
        '<p id="result-count" role="status" aria-live="polite" tabindex="-1"></p>'
        '<p id="empty" hidden>No matching rules. Change your filters or choose Clear filters / show all.</p>'
        '<noscript><p>Enable JavaScript for filters and expandable rule details. Original evidence remains in migration-report.json.</p></noscript>'
        '<div class="table-wrap"><table><caption class="muted">Actionable issues first; individual results remain authoritative.</caption>'
        '<thead><tr><th scope="col">Rule</th><th scope="col">Problem / review reason</th><th scope="col">Next action</th>'
        '<th scope="col">Details</th></tr></thead>' + "".join(rows)
        + f"</table></div></section></main><script>{FILTER_SCRIPT}</script><script>{BULK_SCRIPT}</script></body></html>"
    )
