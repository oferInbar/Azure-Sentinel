from __future__ import annotations

import json
import hashlib
from pathlib import Path
import tempfile
import unittest

import yaml

from sentinel_xdr_migration.runtime import record_runtime_validation, _load_provider_fallback


class RuntimeFallbackEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.solution = Path(self.temp.name) / "Example"
        output = self.solution / "XDR Detections"
        output.mkdir(parents=True)
        source = self.solution / "Analytic Rules/Rule.yaml"
        source.parent.mkdir(parents=True)
        source_query = "DeviceEvents | where TimeGenerated > ago(4h)"
        source.write_text(yaml.safe_dump({
            "id": "11111111-2222-3333-4444-555555555555",
            "query": source_query,
        }), encoding="utf-8")
        self.query_hash = hashlib.sha256(source_query.encode()).hexdigest()
        (output / "Rule.yaml").write_text(yaml.safe_dump({
            "kind": "CustomDetection",
            "contentProvenance": {"source": {"path": "Analytic Rules/Rule.yaml"}},
            "properties": {
                "queryCondition": {"queryText": "DeviceEvents | where Timestamp > ago(4h)"},
                "detectionAction": {"alertTemplate": {}},
            },
        }), encoding="utf-8")
        self.results = Path(self.temp.name) / "results.json"
        self.results.write_text(json.dumps([{
            "detection": "Rule.yaml",
            "status": "passed",
            "statusCode": 200,
            "rowCount": 0,
            "schema": [],
            "querySha256": self.query_hash,
        }]), encoding="utf-8")
        self.evidence = Path(self.temp.name) / "provider-gap.json"
        self.evidence.write_text(json.dumps({
            "mcpProvider": "triage-mcp",
            "advertisedTool": "QueryWorkspace",
            "queryFamily": "sentinel",
            "fallbackProvider": "log-analytics-cli",
            "scopeReference": "/subscriptions/example/resourceGroups/lab/providers/Microsoft.OperationalInsights/workspaces/sentinel",
            "reasonCode": "authorization",
            "reason": "Triage MCP workspace-query permission was unavailable.",
            "batchComplete": True,
            "scopeVerified": True,
            "permissionsVerified": True,
            "kqlError": False,
        }), encoding="utf-8")

    def test_complete_fallback_evidence_is_persisted_without_promoting_status(self):
        result = record_runtime_validation(
            self.solution,
            provider="log-analytics-cli",
            results_path=self.results,
            provider_gap_evidence=self.evidence,
        )
        expected = {
            "mcpProvider": "triage-mcp",
            "advertisedTool": "QueryWorkspace",
            "queryFamily": "sentinel",
            "fallbackProvider": "log-analytics-cli",
            "scopeReference": "/subscriptions/example/resourceGroups/lab/providers/Microsoft.OperationalInsights/workspaces/sentinel",
            "reasonCode": "authorization",
            "reason": "Triage MCP workspace-query permission was unavailable.",
            "batchComplete": True,
            "scopeVerified": True,
            "permissionsVerified": True,
            "kqlError": False,
        }
        self.assertEqual(expected, result["providerFallback"])
        self.assertEqual("passed", result["results"][0]["status"])
        self.assertNotIn("validated", result["results"][0])
        saved = json.loads(Path(result["jsonReport"]).read_text())
        self.assertEqual(expected, saved["providerFallback"])
        self.assertIn("provider gap", Path(result["htmlReport"]).read_text().lower())

    def test_passed_import_requires_exact_current_source_query_hash(self):
        original = json.loads(self.results.read_text())
        for entry in (
            {key: value for key, value in original[0].items() if key != "querySha256"},
            {**original[0], "querySha256": "0" * 64},
        ):
            with self.subTest(querySha256=entry.get("querySha256")):
                self.results.write_text(json.dumps([entry]))
                recorded = record_runtime_validation(
                    self.solution, provider="triage-mcp", results_path=self.results,
                )
                self.assertEqual(1, recorded["blocked"])
                self.assertEqual("blocked", recorded["results"][0]["status"])
                self.assertIn("query hash", recorded["results"][0]["error"].lower())

        self.results.write_text(json.dumps(original))
        source = self.solution / "Analytic Rules/Rule.yaml"
        document = yaml.safe_load(source.read_text())
        document["query"] += " | take 1"
        source.write_text(yaml.safe_dump(document))
        recorded = record_runtime_validation(
            self.solution, provider="triage-mcp", results_path=self.results,
        )
        self.assertEqual(1, recorded["blocked"])
        self.assertIn("stale", recorded["results"][0]["error"].lower())

    def test_kql_failure_stays_failure_and_provider_gap_cannot_mask_it(self):
        failure = {
            "detection": "Rule.yaml",
            "status": "failed",
            "error": "Failed to resolve table 'MissingTable'",
            "querySha256": self.query_hash,
        }
        self.results.write_text(json.dumps([failure]))
        recorded = record_runtime_validation(
            self.solution, provider="triage-mcp", results_path=self.results,
        )
        self.assertEqual(1, recorded["invalid"])
        self.assertEqual("failed", recorded["results"][0]["status"])
        self.assertIn("Failed to resolve table", recorded["results"][0]["error"])
        with self.assertRaisesRegex(ValueError, "fallback is not allowed"):
            record_runtime_validation(
                self.solution,
                provider="log-analytics-cli",
                results_path=self.results,
                provider_gap_evidence=self.evidence,
            )

    def test_fallback_evidence_rejects_kql_errors_incomplete_batches_and_wrong_provider(self):
        for changes, provider in (
            ({"kqlError": True}, "log-analytics-cli"),
            ({"batchComplete": False}, "log-analytics-cli"),
            ({"permissionsVerified": False}, "log-analytics-cli"),
            ({"reasonCode": "kql-semantic-error"}, "log-analytics-cli"),
            ({"fallbackProvider": "graph"}, "log-analytics-cli"),
        ):
            with self.subTest(changes=changes):
                original = json.loads(self.evidence.read_text())
                original.update(changes)
                self.evidence.write_text(json.dumps(original))
                with self.assertRaisesRegex(ValueError, "provider-gap evidence"):
                    _load_provider_fallback(
                        self.evidence,
                        query_family="sentinel",
                        fallback_provider=provider,
                    )
                self.evidence.write_text(json.dumps({
                    "mcpProvider": "triage-mcp",
                    "advertisedTool": "QueryWorkspace",
                    "queryFamily": "sentinel",
                    "fallbackProvider": "log-analytics-cli",
                    "scopeReference": "/subscriptions/example/resourceGroups/lab/providers/Microsoft.OperationalInsights/workspaces/sentinel",
                    "reasonCode": "authorization",
                    "reason": "Triage MCP workspace-query permission was unavailable.",
                    "batchComplete": True,
                    "scopeVerified": True,
                    "permissionsVerified": True,
                    "kqlError": False,
                }))

    def test_provider_gap_contract_is_query_family_scoped(self):
        with self.assertRaisesRegex(ValueError, "provider-gap evidence"):
            _load_provider_fallback(
                self.evidence,
                query_family="advanced-hunting",
                fallback_provider="graph",
            )

    def test_fallback_batch_must_cover_every_detection(self):
        second = self.solution / "XDR Detections" / "Other.yaml"
        second.write_text("kind: CustomDetection\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing detections"):
            record_runtime_validation(
                self.solution,
                provider="log-analytics-cli",
                results_path=self.results,
                provider_gap_evidence=self.evidence,
            )


if __name__ == "__main__":
    unittest.main()
