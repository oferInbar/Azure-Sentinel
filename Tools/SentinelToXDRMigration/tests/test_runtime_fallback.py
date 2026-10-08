from __future__ import annotations

import json
import hashlib
import io
import threading
from pathlib import Path
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import Message
from unittest import mock
import urllib.error
import unittest

import yaml

import sentinel_xdr_migration.runtime as runtime_module
from sentinel_xdr_migration.runtime import (
    _load_provider_fallback,
    record_runtime_validation,
    run_advanced_hunting_query,
    validate_advanced_hunting,
)


def _successful_response():
    response = mock.MagicMock()
    response.status = 200
    response.read.return_value = b'{"results": [], "schema": []}'
    context = mock.MagicMock()
    context.__enter__.return_value = response
    context.__exit__.return_value = False
    return context


def _http_error(status, *, retry_after=None, message="provider failed"):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    body = json.dumps({"error": {"message": message}}).encode()
    return urllib.error.HTTPError(
        runtime_module.ADVANCED_HUNTING_ENDPOINT,
        status,
        "request failed",
        headers,
        io.BytesIO(body),
    )


class _FakeClock:
    def __init__(self, wall_time=1_800_000_000):
        self.elapsed = 0.0
        self.wall_time = wall_time

    def monotonic(self):
        return self.elapsed

    def time(self):
        return self.wall_time + self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds


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


class AdvancedHuntingProviderBoundsTests(unittest.TestCase):
    def test_retry_after_seconds_and_http_date_are_honored(self):
        clock = _FakeClock()
        retry_date = datetime.fromtimestamp(clock.wall_time, timezone.utc) + timedelta(seconds=2)
        urlopen = mock.Mock(
            side_effect=[
                _http_error(429, retry_after="1"),
                _http_error(503, retry_after=retry_date.strftime("%a, %d %b %Y %H:%M:%S GMT")),
                _successful_response(),
            ]
        )
        with (
            mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
            mock.patch.object(runtime_module.time, "monotonic", clock.monotonic),
            mock.patch.object(runtime_module.time, "time", clock.time),
            mock.patch.object(runtime_module.time, "sleep", clock.sleep),
        ):
            result = run_advanced_hunting_query(
                "DeviceEvents | take 1", _token="test-token", timeout=900, retries=99
            )

        self.assertTrue(result["ok"])
        self.assertEqual(3, urlopen.call_count)
        self.assertEqual(2.0, clock.elapsed)
        self.assertEqual([300.0, 299.0, 298.0], [
            call.kwargs["timeout"] for call in urlopen.call_args_list
        ])

    def test_transient_retry_count_is_capped_at_three(self):
        urlopen = mock.Mock(side_effect=[_http_error(503)] * 4)
        with (
            mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
            mock.patch.object(runtime_module.time, "sleep"),
        ):
            result = run_advanced_hunting_query(
                "DeviceEvents | take 1", _token="test-token", retries=99
            )

        self.assertFalse(result["ok"])
        self.assertEqual("provider", result["failureKind"])
        self.assertEqual(4, urlopen.call_count)

    def test_request_duration_consumes_retry_budget_and_bounds_next_timeout(self):
        clock = _FakeClock()

        def slow_transient(*_args, **_kwargs):
            clock.elapsed += 298
            raise _http_error(503, retry_after="1")

        def slow_transient_then_success(*args, **kwargs):
            if urlopen.call_count == 1:
                return slow_transient(*args, **kwargs)
            return _successful_response()

        urlopen = mock.Mock(side_effect=slow_transient_then_success)
        with (
            mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
            mock.patch.object(runtime_module.time, "monotonic", clock.monotonic),
            mock.patch.object(runtime_module.time, "sleep", clock.sleep),
        ):
            result = run_advanced_hunting_query(
                "DeviceEvents | take 1", _token="test-token", timeout=900, retries=3
            )

        self.assertTrue(result["ok"])
        self.assertEqual([300, 1], [
            call.kwargs["timeout"] for call in urlopen.call_args_list
        ])
        self.assertEqual(299, clock.elapsed)

    def test_exhausted_wall_clock_budget_does_not_retry(self):
        clock = _FakeClock()

        def exhaust_budget(*_args, **_kwargs):
            clock.elapsed += 300
            raise _http_error(503, retry_after="1")

        urlopen = mock.Mock(side_effect=exhaust_budget)
        sleeper = mock.Mock()
        with (
            mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
            mock.patch.object(runtime_module.time, "monotonic", clock.monotonic),
            mock.patch.object(runtime_module.time, "sleep", sleeper),
        ):
            result = run_advanced_hunting_query(
                "DeviceEvents | take 1", _token="test-token", retries=3
            )

        self.assertFalse(result["ok"])
        self.assertEqual("provider", result["failureKind"])
        self.assertEqual(1, urlopen.call_count)
        sleeper.assert_not_called()

    def test_retry_after_larger_than_remaining_budget_is_not_followed(self):
        clock = _FakeClock()

        def slow_transient(*_args, **_kwargs):
            clock.elapsed += 299
            raise _http_error(429, retry_after="2")

        urlopen = mock.Mock(side_effect=slow_transient)
        sleeper = mock.Mock()
        with (
            mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
            mock.patch.object(runtime_module.time, "monotonic", clock.monotonic),
            mock.patch.object(runtime_module.time, "sleep", sleeper),
        ):
            result = run_advanced_hunting_query(
                "DeviceEvents | take 1", _token="test-token", retries=3
            )

        self.assertFalse(result["ok"])
        self.assertEqual(1, urlopen.call_count)
        sleeper.assert_not_called()

    @mock.patch(
        "sentinel_xdr_migration.runtime._advanced_hunting_token",
        return_value="test-token",
    )
    @mock.patch("sentinel_xdr_migration.runtime.run_advanced_hunting_query")
    def test_graph_validation_uses_converted_query_and_its_exact_hash(
        self, run_query, _token
    ):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            solution = Path(temp) / "Example"
            source_query = "DeviceEvents | where TimeGenerated > ago(4h)"
            converted_query = "DeviceEvents | where Timestamp > ago(4h)"
            source = solution / "Analytic Rules" / "Rule.yaml"
            source.parent.mkdir(parents=True)
            source.write_text(
                yaml.safe_dump({"query": source_query}), encoding="utf-8"
            )
            output = solution / "XDR Detections"
            output.mkdir()
            (output / "Rule.yaml").write_text(
                yaml.safe_dump({
                    "contentProvenance": {
                        "source": {"path": "Analytic Rules/Rule.yaml"}
                    },
                    "properties": {
                        "queryCondition": {"queryText": converted_query}
                    },
                }),
                encoding="utf-8",
            )
            run_query.return_value = {
                "ok": True,
                "statusCode": 200,
                "rowCount": 0,
                "schema": [],
                "error": None,
                "errorDetails": None,
            }

            report = validate_advanced_hunting(solution)

        self.assertEqual("graph", report["provider"])
        self.assertEqual(
            ["DeviceEvents | take 0", converted_query],
            [call.args[0] for call in run_query.call_args_list],
        )
        self.assertEqual(
            hashlib.sha256(converted_query.encode()).hexdigest(),
            report["results"][0]["querySha256"],
        )

    def test_authentication_and_kql_errors_are_not_retried(self):
        for status, failure_kind in ((401, "provider"), (403, "provider"), (400, "query")):
            with self.subTest(status=status):
                urlopen = mock.Mock(side_effect=_http_error(status))
                with (
                    mock.patch.object(runtime_module.urllib.request, "urlopen", urlopen),
                    mock.patch.object(runtime_module.time, "sleep") as sleeper,
                ):
                    result = run_advanced_hunting_query(
                        "DeviceEvents | take 1", _token="test-token", retries=3
                    )
                self.assertFalse(result["ok"])
                self.assertEqual(failure_kind, result["failureKind"])
                self.assertEqual(1, urlopen.call_count)
                sleeper.assert_not_called()

    def test_at_most_five_graph_requests_are_in_flight(self):
        lock = threading.Lock()
        active = 0
        peak = 0
        calls = 0
        five_started = threading.Event()
        release_requests = threading.Event()

        def blocked_urlopen(*_args, **_kwargs):
            nonlocal active, peak, calls
            with lock:
                calls += 1
                active += 1
                peak = max(peak, active)
                if active == 5:
                    five_started.set()
            if not release_requests.wait(5):
                raise AssertionError("test did not release blocked request")
            with lock:
                active -= 1
            return _successful_response()

        with mock.patch.object(
            runtime_module.urllib.request, "urlopen", blocked_urlopen
        ):
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [
                    executor.submit(
                        run_advanced_hunting_query,
                        "DeviceEvents | take 1",
                        _token="test-token",
                    )
                    for _ in range(10)
                ]
                self.assertTrue(five_started.wait(3))
                with lock:
                    self.assertEqual(5, active)
                threading.Event().wait(0.05)
                with lock:
                    self.assertEqual(5, calls)
                release_requests.set()
                results = [future.result(timeout=5) for future in futures]

        self.assertTrue(all(result["ok"] for result in results))
        self.assertEqual(5, peak)
        self.assertEqual(10, calls)

    @mock.patch(
        "sentinel_xdr_migration.runtime._advanced_hunting_token",
        return_value="test-token",
    )
    @mock.patch("sentinel_xdr_migration.runtime.run_advanced_hunting_query")
    def test_shared_provider_failure_is_not_reported_as_rule_error(
        self, run_query, _token
    ):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            solution = Path(temp) / "Example"
            output = solution / "XDR Detections"
            output.mkdir(parents=True)
            query = "DeviceEvents | where Timestamp > ago(4h)"
            (output / "Rule.yaml").write_text(
                yaml.safe_dump({
                    "properties": {"queryCondition": {"queryText": query}},
                }),
                encoding="utf-8",
            )
            run_query.return_value = {
                "ok": False,
                "statusCode": 503,
                "rowCount": 0,
                "schema": [],
                "error": "Graph is temporarily unavailable",
                "errorDetails": "shared provider outage",
                "failureKind": "provider",
            }

            report = validate_advanced_hunting(solution)

            self.assertEqual(0, report["invalid"])
            self.assertEqual(0, report["blocked"])
            self.assertEqual(1, report["notRun"])
            self.assertEqual("graph", report["providerFailure"]["provider"])
            self.assertEqual("not-run", report["results"][0]["status"])
            self.assertIsNone(report["results"][0]["error"])
            self.assertEqual(
                hashlib.sha256(query.encode()).hexdigest(),
                report["results"][0]["querySha256"],
            )
            self.assertEqual(["DeviceEvents | take 0"], [
                call.args[0] for call in run_query.call_args_list
            ])


if __name__ == "__main__":
    unittest.main()
