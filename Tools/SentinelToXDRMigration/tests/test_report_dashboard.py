from __future__ import annotations

import ast
from copy import deepcopy
from html.parser import HTMLParser
from pathlib import Path
import unittest

from sentinel_xdr_migration.report_dashboard import _chart_bucket, _findings, _findings_chart_html, _rule_status, _tactic_details, render_dashboard


def rule(name: str = "Example") -> dict:
    return {
        "name": name, "sourceFile": "Analytic Rules/Example.yaml",
        "outputFile": "XDR Detections/Example.yaml",
        "analyticRule": {"id": "source-id", "runtime": [], "deploymentStatus": "not-recorded", "alertStatus": "not-run"},
        "customDetection": {
            "id": "output-id", "conversionStatus": "converted", "structuralStatus": "passed",
            "reviewRequired": False, "reviewReasons": [], "runtime": [],
            "deploymentStatus": "not-run", "alertStatus": "not-run",
        },
        "errors": [], "warnings": [],
        "queryParity": {"status": "not-run", "analyticRuleRows": None, "customDetectionRows": None, "matchKey": None},
        "queries": {"source": "DeviceEvents\n| take 1", "converted": "DeviceEvents\n| take 2"},
    }


def report(*rules: dict) -> dict:
    return {
        "solution": "Example solution", "generatedAt": "2026-10-07",
        "summary": {"converted": len(rules), "needsReview": 0, "deploymentReady": len(rules)},
        "workflow": {
            "runId": "example-run", "profile": "authoring", "status": "blocked",
            "workspaceConfigured": False,
            "stages": {
                "conversion": {"status": "blocked", "message": "Semantic decisions remain; runtime not attempted.", "evidence": []},
                "validation": {"status": "pending"},
                "deployment": {"status": "notRequired"},
            },
        },
        "rules": list(rules),
    }


class Structure(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.controls: list[str] = []
        self.scripts = 0
        self.statuses: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        values = dict(attrs)
        if "id" in values:
            self.ids.append(values["id"])
        if "aria-controls" in values:
            self.controls.append(values["aria-controls"])
        if tag == "script":
            self.scripts += 1
        if tag == "tbody" and values.get("class") == "rule":
            self.statuses.append(values["data-status"])


class ReportDashboardTests(unittest.TestCase):
    def test_python_311_syntax(self) -> None:
        path = Path(__file__).parents[1] / "sentinel_xdr_migration" / "report_dashboard.py"
        ast.parse(path.read_text(), feature_version=(3, 11))

    def test_current_run_counts_do_not_claim_25_ready(self) -> None:
        rules = [rule(f"Rule {index}") for index in range(40)]
        for item in rules[:15]:
            item["customDetection"].update(
                conversionStatus="needsReview", reviewRequired=True,
                reviewReasons=["Choose a tactic"],
            )
        value = report(*rules)
        value["summary"].update(converted=25, needsReview=15)
        before = deepcopy(value)
        html = render_dashboard(value)
        self.assertEqual(value, before)
        for text in ("All (40)", "Needs review (15)", "Ready for validation (0)",
                     "Readiness unconfirmed (25)", "Blocked / Failed (0)",
                     "40 local structural passes", "25 automated conversions"):
            self.assertIn(text, html)
        self.assertNotIn("Deployment ready", html)
        self.assertNotIn("AR rows: None", html)
        self.assertEqual(html.count("Semantic decisions remain; runtime not attempted."), 1)
        self.assertNotIn("deployment: not-run", html)

    def test_status_precedence_and_recorded_gate(self) -> None:
        item = rule()
        workflow = report(item)["workflow"]
        self.assertEqual(_rule_status(item, workflow), "unconfirmed")
        workflow["stages"]["conversion"]["status"] = "passed"
        self.assertEqual(_rule_status(item, workflow), "ready")
        item["customDetection"]["reviewReasons"] = ["Confirm identity"]
        self.assertEqual(_rule_status(item, workflow), "review")
        item["customDetection"]["runtime"] = [{"status": "blocked"}]
        self.assertEqual(_rule_status(item, workflow), "failed")
        item["customDetection"]["runtime"] = []
        item["customDetection"]["deploymentStatus"] = "failed"
        self.assertEqual(_rule_status(item, workflow), "failed")
        item = rule()
        item["customDetection"]["conversionStatus"] = "not-run"
        self.assertEqual(_rule_status(item, workflow), "notstarted")
        item["customDetection"]["conversionStatus"] = "excluded"
        self.assertEqual(_rule_status(item, workflow), "excluded")

    def test_dedupe_keeps_diagnostic_stages_and_raw_details(self) -> None:
        item = rule()
        item["errors"] = [
            {"stage": "conversion", "message": "Required output missing", "code": "LOCAL", "details": {"original": True}},
            {"stage": "structural-validation", "message": "conversion: Required output missing", "code": "CHECK"},
        ]
        item["customDetection"]["reviewReasons"] = ["Confirm entity"]
        item["warnings"] = ["Confirm entity"]
        findings = _findings(item)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0]["stages"], ["conversion", "structural-validation"])
        self.assertEqual(len(findings[0]["evidence"]), 2)
        self.assertEqual(findings[0]["evidence"][0]["details"], {"original": True})
        self.assertEqual(findings[1]["severity"], "review")
        html = render_dashboard(report(item))
        self.assertIn("1 distinct rule errors · 2 diagnostic occurrences", html)

    def test_provider_gap_is_visible_as_information_not_runtime_parity(self) -> None:
        item = rule()
        item["analyticRule"]["runtime"] = [{
            "provider": "log-analytics-cli",
            "status": "passed",
            "providerFallback": {
                "mcpProvider": "triage-mcp",
                "advertisedTool": "QueryWorkspace",
                "fallbackProvider": "log-analytics-cli",
                "queryFamily": "sentinel",
                "scopeReference": "/subscriptions/example/resourceGroups/lab/providers/Microsoft.OperationalInsights/workspaces/sentinel",
                "reasonCode": "authorization",
                "reason": "MCP workspace-query tool was unavailable.",
                "batchComplete": True,
                "scopeVerified": True,
                "permissionsVerified": True,
                "kqlError": False,
            },
        }]
        findings = _findings(item)
        self.assertTrue(any(
            value["severity"] == "info" and "provider gap" in value["message"].lower()
            for value in findings
        ))
        self.assertEqual("unconfirmed", _rule_status(item, report(item)["workflow"]))
        html = render_dashboard(report(item))
        self.assertIn("MCP workspace-query tool was unavailable.", html)
        self.assertNotIn("parity passed", html.lower())
        self.assertIn("Automated check overview", html)
        self.assertIn("local structural checks", html)

    def test_common_findings_count_rules_and_preserve_original_override(self) -> None:
        first, second = rule("First"), rule("Second")
        for number, item in enumerate((first, second)):
            text = f"Choose tactic in ruleOverrides.11111111-1111-1111-1111-11111111111{number}.tactic"
            item["customDetection"]["reviewReasons"] = [text]
            item["warnings"] = [text]
        html = render_dashboard(report(first, second))
        self.assertIn("Show 2 affected rules", html)
        self.assertIn("ruleOverrides.&lt;rule-id&gt;.tactic", html)
        self.assertIn("ruleOverrides.11111111-1111-1111-1111-111111111110.tactic", html)

    def test_exceptions_visible_despite_not_required_and_zero_preserved(self) -> None:
        item = rule()
        item["customDetection"]["runtime"] = [
            {"provider": "graph", "status": "failed", "rowCount": 0},
            {"provider": "another-provider", "status": "blocked", "rowCount": None},
        ]
        item["errors"] = [{"stage": "custom-detection-runtime-validation", "message": "Permission denied"}]
        html = render_dashboard(report(item))
        self.assertIn("Deployment: Not required", html)
        self.assertIn("Blocked / Failed (1)", html)
        self.assertIn("graph: Failed · 0 rows", html)
        self.assertIn("another-provider: Blocked · Row count unavailable", html)
        self.assertIn("Permission denied", html)

    def test_missing_evidence_not_global_skip(self) -> None:
        value = report(rule())
        value.pop("workflow")
        html = render_dashboard(value)
        self.assertIn("Workflow stage evidence unavailable", html)
        self.assertNotIn("Deployment: Not required", html)
        self.assertIn("Runtime evidence available for 0 of 1 rules", html)

    def test_escape_untrusted_text_and_accessible_structure(self) -> None:
        payload = '</script><script>alert("injected")</script><img src=x onerror=alert(1)>'
        item = rule(payload)
        item["queries"]["converted"] = payload
        item["warnings"] = [payload]
        item["sourceFile"] = payload
        value = report(item)
        value["workflow"]["stages"]["conversion"]["message"] = payload
        html = render_dashboard(value)
        parser = Structure()
        parser.feed(html)
        self.assertEqual(parser.scripts, 3)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        self.assertTrue(set(parser.controls).issubset(parser.ids))
        self.assertNotIn(payload, html)
        self.assertIn("&lt;/script&gt;", html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('type="radio" name="status" value="attention" checked', html)
        self.assertIn('html[data-theme="dark"]', html)
        self.assertIn("Unified text diff", html)

    def test_unchanged_and_absent_queries(self) -> None:
        item = rule()
        item["queries"]["converted"] = item["queries"]["source"]
        self.assertIn("Query unchanged", render_dashboard(report(item)))
        item["queries"]["converted"] = None
        self.assertIn("Comparison unavailable", render_dashboard(report(item)))
        item.pop("queries")
        self.assertNotIn("<summary>Source / converted queries", render_dashboard(report(item)))

    def test_warning_never_implies_error_review_or_failed_readiness(self) -> None:
        item = rule()
        item["warnings"] = ["source queryPeriod has no direct Custom Detection schedule field; verify the KQL lookback"]
        value = report(item)
        self.assertEqual(_rule_status(item, value["workflow"]), "unconfirmed")
        value["workflow"]["stages"]["conversion"]["status"] = "passed"
        self.assertEqual(_rule_status(item, value["workflow"]), "ready")
        findings = _findings(item)
        self.assertEqual([finding["severity"] for finding in findings], ["warning"])
        html = render_dashboard(value)
        for text in ("Warnings (1 rules)", "Errors (0 rules)", "Reviews (0 rules)",
                     "Ready for validation (1)", 'data-findings="warning"', "nonblocking advisories"):
            self.assertIn(text, html)
        self.assertIn('data-evidence-kind="warning"', html)

    def test_actual_failed_and_blocked_checks_are_distinct(self) -> None:
        failed, blocked = rule("Failed"), rule("Blocked")
        failed["customDetection"]["runtime"] = [{"status": "failed", "provider": "graph", "rowCount": 0}]
        blocked["customDetection"]["runtime"] = [{"status": "blocked", "provider": "graph"}]
        blocked["errors"] = [{
            "stage": "custom-detection-runtime-validation", "provider": "graph", "message": "Missing prerequisite",
        }]
        self.assertEqual([finding["severity"] for finding in _findings(failed)], ["error"])
        self.assertEqual([finding["severity"] for finding in _findings(blocked)], ["blocked"])
        html = render_dashboard(report(failed, blocked))
        self.assertIn("Errors (1 rules)", html)
        self.assertIn("Blocked prerequisites (1 rules)", html)
        self.assertIn("Blocked — not an execution failure", html)

    def test_explicit_review_deduplicates_matching_warning_without_promoting_others(self) -> None:
        item = rule()
        item["customDetection"]["reviewReasons"] = ["Choose tactic"]
        item["warnings"] = ["Choose tactic", "Verify schedule"]
        item["errors"] = [{"stage": "conversion", "message": "Hard failure"}]
        findings = _findings(item)
        self.assertEqual([finding["severity"] for finding in findings], ["error", "review", "warning"])
        self.assertEqual(findings[1]["stages"], ["conversion-review", "conversion-warning"])
        html = render_dashboard(report(item))
        self.assertIn("Errors (1 rules)", html)
        self.assertIn("Reviews (1 rules)", html)
        self.assertIn("Warnings (1 rules)", html)

    def test_explicit_review_flag_without_reason_has_review_finding(self) -> None:
        item = rule()
        item["customDetection"]["reviewRequired"] = True
        self.assertEqual(_findings(item)[0]["severity"], "review")
        self.assertIn("Reviews (1 rules)", render_dashboard(report(item)))

    def test_information_has_no_readiness_or_attention_effect(self) -> None:
        item = rule()
        item["informational"] = ["Mapped entity equivalently", "Frequency and effective window match"]
        value = report(item)
        value["workflow"]["stages"]["conversion"]["status"] = "passed"
        self.assertEqual(_rule_status(item, value["workflow"]), "ready")
        self.assertEqual(_chart_bucket(item), "green")
        html = render_dashboard(value)
        for text in ("Needs attention (0)", "Warnings (0 rules)", "Errors (0 rules)", "Reviews (0 rules)",
                     "Information (1 rules)", 'data-evidence-kind="info"', 'data-chart="green"'):
            self.assertIn(text, html)
        item["warnings"] = ["Frequency and effective window match"]
        self.assertEqual({finding["severity"] for finding in _findings(item)}, {"warning", "info"})
        self.assertEqual(_chart_bucket(item), "yellow")

    def test_chart_counts_each_rule_once_by_priority(self) -> None:
        green, yellow, red, gray, blocked = [rule(name) for name in ("Green", "Yellow", "Red", "Gray", "Blocked")]
        green["informational"] = ["Nonblocking mapping note"]
        yellow["warnings"] = ["Different effective window"]
        yellow["customDetection"]["reviewReasons"] = ["Select tactic"]
        red["errors"] = [{"stage": "conversion", "message": "Hard error"}]
        red["warnings"] = ["Warning too"]
        red["customDetection"]["reviewReasons"] = ["Review too"]
        gray["customDetection"].update(conversionStatus="not-run", structuralStatus="not-generated")
        blocked["customDetection"]["runtime"] = [{"status": "blocked", "provider": "graph"}]
        self.assertEqual([_chart_bucket(item) for item in (green, yellow, red, gray, blocked)],
                         ["green", "yellow", "red", "gray", "gray"])
        html = render_dashboard(report(green, yellow, red, gray, blocked))
        for text in ("Automated checks passed: 1 rules (20.0%)", "Warnings or review required: 1 rules (20.0%)",
                     "Errors: 1 rules (20.0%)", "Readiness unconfirmed: 2 rules (40.0%)",
                     'class="chart-total" x="21" y="21">5'):
            self.assertIn(text, html)
        self.assertIn('tabindex="0" role="button"', html)
        self.assertIn("Readiness unconfirmed in the status filter", html)

    def test_findings_pie_counts_findings_not_rules_and_keeps_green_separate(self) -> None:
        mixed = rule("Mixed")
        mixed["errors"] = [
            {"stage": "conversion", "message": "Failure"},
            {"stage": "structural-validation", "message": "conversion: Failure"},
        ]
        mixed["customDetection"]["reviewReasons"] = ["Choose tactic"]
        mixed["warnings"] = ["Choose tactic", "Window differs", "Window differs"]
        mixed["informational"] = ["Equivalent", "Equivalent"]
        clean, info, blocked = rule("Clean"), rule("Info"), rule("Blocked")
        info["informational"] = ["Matched mapping"]
        blocked["customDetection"]["runtime"] = [{"status": "blocked", "provider": "graph"}]
        html = _findings_chart_html([mixed, clean, info, blocked])
        for text in ("5 distinct findings", "Errors: 1 findings (20.0%)",
                     "Warnings / reviews: 2 findings (40.0%)", "Informational: 2 findings (40.0%)",
                     "<strong>2 rules</strong> passed automated checks", "Blocked prerequisite findings (1)"):
            self.assertIn(text, html)
        self.assertNotIn('class="pie-green"', html)
        self.assertIn('data-findings-chart-filter="attention"', html)

    def test_findings_pie_handles_empty_and_single_category(self) -> None:
        self.assertIn("0 distinct findings", _findings_chart_html([]))
        self.assertIn('class="pie-empty"', _findings_chart_html([]))
        item = rule()
        item["informational"] = ["Only info"]
        html = _findings_chart_html([item])
        self.assertIn('<circle cx="21" cy="21" r="18" class="pie-info"', html)
        self.assertIn("Informational: 1 findings (100.0%)", html)

    def test_multi_tactic_source_shows_exact_unapproved_draft_and_one_shared_guide(self) -> None:
        item = rule("Three tactic source")
        item["customDetection"]["reviewReasons"] = [
            "Custom Detections support one tactic; configure ruleOverrides.source-id.tactic and techniques"
        ]
        item["attackClassification"] = {
            "sourceTactics": ["Execution", "Collection", "Exfiltration"],
            "sourceTechniques": ["T1059", "T1005", "T1020"],
            "originalTactics": ["Execution", "Collection", "Exfiltration"],
            "originalTechniques": ["T1059", "T1005", "T1020"],
            "draftTactics": [{"tactic": "Execution"}],
        }
        html = render_dashboard(report(item, deepcopy(item)))
        self.assertEqual(html.count('id="tactic-selection-guide"'), 1)
        for text in ("Unapproved fallback shape", "techniques omitted", "independent list",
                     "multiple compatible techniques and subtechniques", "not one technique only",
                     "Multiple tactics alone no longer require review", "T1059", "T1005", "T1020",
                     "Preserve source tactics; review historical single-tactic findings", "collection-shaped property",
                     "not a claim", "ARM was tested"):
            self.assertIn(text, html)
        self.assertIn("Errors (0 rules)", html)
        self.assertIn("Reviews (2 rules)", html)

    def test_compatible_multiple_techniques_are_not_reported_as_fallback(self) -> None:
        item = rule()
        item["customDetection"]["reviewReasons"] = ["Custom Detections support one tactic"]
        item["attackClassification"] = {
            "originalTactics": ["Execution", "Collection"],
            "draftTactics": [{"tactic": "Execution", "techniques": [
                {"technique": "T1059", "subTechniques": ["T1059.001"]},
                {"technique": "T1106"},
            ]}],
        }
        html = render_dashboard(report(item))
        self.assertNotIn("Unapproved fallback shape", html)
        self.assertIn("T1059.001", html)
        self.assertIn("T1106", html)
        self.assertIn("Classification metadata not recorded", html)
        self.assertIn("not treated as proof that a selection was approved", html)

    def test_tactic_metadata_and_rule_specific_example_are_escaped_not_selected(self) -> None:
        class PreText(HTMLParser):
            def __init__(self) -> None:
                super().__init__()
                self.blocks = []
                self.active = False

            def handle_starttag(self, tag, attrs):
                if tag == "pre":
                    self.active = True
                    self.blocks.append("")

            def handle_endtag(self, tag):
                if tag == "pre":
                    self.active = False

            def handle_data(self, data):
                if self.active:
                    self.blocks[-1] += data

        import json

        payload = '</pre><script>alert("classification")</script>'
        item = rule()
        item["analyticRule"]["id"] = payload
        item["customDetection"]["reviewReasons"] = ["Custom Detections support one tactic"]
        item["attackClassification"] = {"sourceTactics": [payload], "draftTactics": [{"tactic": payload}]}
        html = _tactic_details(item, _findings(item))
        self.assertNotIn(payload, html)
        parser = PreText()
        parser.feed(html)
        example = json.loads(parser.blocks[-1])
        self.assertEqual(list(example["ruleOverrides"]), [payload])
        override = example["ruleOverrides"][payload]
        self.assertEqual(override["tactic"], "<existing source tactic whose techniques need correction>")
        self.assertEqual(len(override["techniques"]), 2)
        self.assertTrue(all(value.startswith("<") for value in override["techniques"]))
        self.assertIn("illustrative, not ready to apply", html)


if __name__ == "__main__":
    unittest.main()
