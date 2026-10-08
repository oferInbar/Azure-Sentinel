from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from sentinel_xdr_migration.converter import (
    build_xdr_document,
    convert_solution,
    custom_detail_schema_errors,
    runtime_validation_plan,
    validate_document,
)
from sentinel_xdr_migration.deployment import graph_detection_payload
from sentinel_xdr_migration.runtime import record_runtime_validation, validate_advanced_hunting
from test_conversion_semantics import HOST_QUERY, entity
from test_converter import RULE


class SupplementalCustomDetailsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.solution = Path(self.directory.name) / "Example"
        self.source = self.solution / "Analytic Rules/Rule.yaml"
        self.source.parent.mkdir(parents=True)
        self.rule = yaml.safe_load(RULE)
        self.rule["query"] = "DeviceEvents | project DeviceName, HostName, SourceIP, Evidence, Other"
        self.rule["entityMappings"] = [
            entity("Host", FullName="DeviceName", HostName="HostName"),
            entity("IP", Address="SourceIP"),
        ]

    def build(self, override=None, config=None):
        self.source.write_text(yaml.safe_dump(self.rule, sort_keys=False))
        settings = deepcopy(config or {})
        settings["ruleOverrides"] = {self.rule["id"]: override or {}}
        return build_xdr_document(self.source, self.solution, settings)

    @staticmethod
    def alert(document):
        return document["properties"]["detectionAction"]["alertTemplate"]

    @staticmethod
    def conversion(document):
        return document["contentProvenance"]["conversion"]

    def test_fullname_is_supplemental_not_an_entity_replacement(self):
        document = self.build()
        alert = self.alert(document)
        self.assertEqual(alert["customDetails"], {"HostFullName": "DeviceName"})
        self.assertEqual(alert["entityMappings"]["hosts"][0]["nameColumn"], "HostName")
        self.assertEqual(alert["entityMappings"]["ips"][0]["addressColumn"], "SourceIP")
        self.assertNotIn("fullNameColumn", alert["entityMappings"]["hosts"][0])
        conversion = self.conversion(document)
        self.assertTrue(any("converter cannot map Host.FullName" in warning for warning in conversion["warnings"]))
        self.assertTrue(any("do not restore entity identity" in warning for warning in conversion["warnings"]))
        self.assertTrue(any("Host.FullName" in note and "customDetails.HostFullName" in note for note in conversion["informational"]))
        self.assertEqual(conversion["supplementalEntityDetails"], [{
            "entityType": "Host", "entityIndex": 1, "identifier": "FullName",
            "sourceColumn": "DeviceName", "column": "DeviceName",
            "status": "available", "customDetailKey": "HostFullName",
        }])
        self.assertEqual(validate_document(document), [])
        payload = graph_detection_payload(document)
        self.assertEqual(payload["detectionAction"]["alertTemplate"]["customDetails"], alert["customDetails"])
        self.assertNotIn("contentProvenance", payload)

    def test_explicit_mapping_override_still_preserves_original_values(self):
        override = {"entityMappings": {
            "hosts": [{"id": "host1", "nameColumn": "Other"}],
            "ips": [{"id": "ip1", "addressColumn": "SourceIP"}],
        }}
        document = self.build(override)
        self.assertEqual(self.alert(document)["entityMappings"], override["entityMappings"])
        self.assertEqual(self.alert(document)["customDetails"], {
            "HostFullName": "DeviceName", "HostHostName": "HostName",
        })
        self.assertTrue(any("Host.HostName" in value for value in self.conversion(document)["warnings"]))

    def test_proven_equivalent_fullname_needs_no_duplicate_detail(self):
        self.rule["query"] = HOST_QUERY
        self.rule["entityMappings"] = [
            entity("Host", FullName="DeviceName", HostName="HostName", DnsDomain="DnsDomain"),
        ]
        document = self.build()
        self.assertNotIn("customDetails", self.alert(document))
        self.assertNotIn("supplementalEntityDetails", self.conversion(document))

    def test_missing_projected_away_or_renamed_columns_do_not_add_invalid_bindings(self):
        for query in (
            "DeviceEvents | project HostName, SourceIP",
            "DeviceEvents | project DeviceName, HostName, SourceIP | project HostName, SourceIP",
            "DeviceEvents | project DeviceName, HostName, SourceIP | project-away DeviceName",
            "DeviceEvents | project DeviceName, HostName, SourceIP | project-rename Other=DeviceName",
            "DeviceEvents | project DeviceName, HostName, SourceIP | sort by SourceIP | project HostName, SourceIP",
        ):
            with self.subTest(query=query):
                self.rule["query"] = query
                document = self.build()
                self.assertNotIn("customDetails", self.alert(document))
                self.assertTrue(any("not preserved" in value for value in self.conversion(document)["warnings"]))
                self.assertEqual(self.conversion(document)["supplementalEntityDetails"][0]["status"], "not-preserved")
                self.assertEqual(document["properties"]["queryCondition"]["queryText"], query)

    def test_unknown_output_emits_pending_binding_not_false_proof(self):
        self.rule["query"] = "DeviceEvents"
        document = self.build()
        self.assertEqual(self.alert(document)["customDetails"], {"HostFullName": "DeviceName"})
        self.assertEqual(self.conversion(document)["supplementalEntityDetails"][0]["status"], "runtime-binding-pending")
        self.assertTrue(any("requires runtime output-schema" in value for value in self.conversion(document)["warnings"]))
        self.assertTrue(custom_detail_schema_errors(document, [{"Name": "Other"}]))
        self.assertEqual(custom_detail_schema_errors(document, [{"name": "DeviceName"}]), [])

    def test_collision_suffixes_existing_keys_and_duplicate_values(self):
        self.rule["customDetails"] = {"HostFullName": "Evidence", "Original": "Other"}
        self.rule["entityMappings"].insert(1, entity("Host", FullName="Other"))
        self.rule["entityMappings"].insert(2, entity("Host", FullName="DeviceName"))
        document = self.build({"customDetails": {"Reviewed": "SourceIP"}})
        self.assertEqual(self.alert(document)["customDetails"], {
            "HostFullName": "Evidence", "Original": "Other", "Reviewed": "SourceIP",
            "HostFullName_2": "DeviceName",
        })
        records = self.conversion(document)["supplementalEntityDetails"]
        self.assertEqual([entry["customDetailKey"] for entry in records], ["HostFullName_2", "Original", "HostFullName_2"])
        self.assertEqual([entry["entityIndex"] for entry in records], [1, 2, 3])
        before = deepcopy(self.rule)
        self.assertEqual(document, self.build({"customDetails": {"Reviewed": "SourceIP"}}))
        self.assertEqual(self.rule, before)

    def test_conflicting_explicit_key_is_blocking_without_overwrite(self):
        self.rule["customDetails"] = {"Keep": "Evidence"}
        document = self.build({"customDetails": {"Keep": "Other", "Add": "SourceIP"}})
        self.assertEqual(self.alert(document)["customDetails"]["Keep"], "Evidence")
        self.assertEqual(self.alert(document)["customDetails"]["Add"], "SourceIP")
        self.assertTrue(any("conflicts" in error for error in self.conversion(document)["errors"]))
        self.assertTrue(validate_document(document))

    def test_source_and_configured_column_renames_apply_to_details_and_entities(self):
        self.rule["query"] = "IdentityInfo | project AccountUPN, SourceIP, Evidence"
        self.rule["entityMappings"] = [entity("Process", CommandLine="AccountUPN"), entity("IP", Address="SourceIP")]
        self.rule["customDetails"] = {"Existing": "AccountUPN"}
        document = self.build(config={"columnMappings": {"Evidence": "Renamed"}})
        self.assertEqual(self.alert(document)["customDetails"], {"Existing": "AccountUpn"})
        self.assertEqual(self.conversion(document)["supplementalEntityDetails"][0]["sourceColumn"], "AccountUPN")
        self.assertEqual(self.conversion(document)["supplementalEntityDetails"][0]["column"], "AccountUpn")
        self.assertIn("AccountUpn", document["properties"]["queryCondition"]["queryText"])
        self.assertIn("Renamed", document["properties"]["queryCondition"]["queryText"])

    def test_every_unmapped_entity_family_uses_same_preservation_path(self):
        for kind, identifier in [
            ("DNS", "DnsServerIp"), ("File", "Directory"), ("FileHash", "Value"),
            ("Process", "ProcessId"), ("RegistryValue", "Value"), ("SecurityGroup", "Name"),
            ("Account", "DisplayName"), ("CloudApplication", "AppType"), ("Mailbox", "DisplayName"),
            ("MailMessage", "Body"), ("MailCluster", "Count"), ("AzureResource", "SubscriptionId"),
            ("IP", "Location"), ("URL", "Domain"), ("UnknownFamily", "Identifier"),
        ]:
            with self.subTest(kind=kind):
                self.rule["entityMappings"] = [entity(kind, **{identifier: "Evidence"}), entity("IP", Address="SourceIP")]
                document = self.build()
                self.assertEqual(self.alert(document)["customDetails"], {kind + identifier: "Evidence"})

    def test_ambiguous_account_mapping_keeps_review_and_original_value(self):
        self.rule["query"] = "DeviceEvents | project ShortName"
        self.rule["entityMappings"] = [entity("Account", Name="ShortName")]
        document = self.build()
        self.assertTrue(self.conversion(document)["reviewRequired"])
        self.assertEqual(self.alert(document)["customDetails"], {"AccountName": "ShortName"})
        self.assertEqual(self.alert(document)["entityMappings"]["accounts"][0]["upnColumn"], "ShortName")

    def test_malformed_explicit_details_and_pair_limit_fail_without_truncation(self):
        for details in (None, [], "value", {"Bad": 1}, {"Bad": ""}, {"": "Evidence"}):
            with self.subTest(details=details):
                self.rule["customDetails"] = details
                document = self.build()
                self.assertTrue(self.conversion(document)["errors"])
                self.assertTrue(validate_document(document))
        self.rule["customDetails"] = {f"Key{index}": "Evidence" for index in range(20)}
        document = self.build()
        self.assertEqual(len(self.alert(document)["customDetails"]), 21)
        self.assertTrue(any("20-pair limit" in error for error in self.conversion(document)["errors"]))
        self.assertTrue(validate_document(document))
        self.assertTrue(any("4 KB" in value for value in self.conversion(document)["warnings"]))
        self.rule.pop("customDetails")
        self.assertTrue(self.conversion(self.build({"customDetails": "bad"}))["errors"])
        self.rule["customDetails"] = {"A" * 4097: "Evidence"}
        document = self.build()
        self.assertTrue(any("keys alone exceed" in error for error in validate_document(document)))

    def test_empty_details_and_empty_entities_do_not_invent_supplements(self):
        self.rule["customDetails"] = {}
        self.rule["entityMappings"] = [entity("IP", Address="SourceIP")]
        document = self.build()
        self.assertEqual(self.alert(document)["customDetails"], {})
        self.assertNotIn("supplementalEntityDetails", self.conversion(document))
        self.rule["entityMappings"] = []
        self.assertEqual(self.alert(self.build())["customDetails"], {})

    def test_reconversion_is_stable_and_source_is_unchanged(self):
        self.build()
        before = self.source.read_bytes()
        first = convert_solution(self.solution)
        output = self.solution / "XDR Detections/Rule.yaml"
        draft = output.read_bytes()
        second = convert_solution(self.solution)
        self.assertEqual(first["converted"], 1)
        self.assertEqual(second["conflicts"], 0)
        self.assertEqual(draft, output.read_bytes())
        self.assertEqual(before, self.source.read_bytes())
        plan = runtime_validation_plan(self.solution)
        self.assertEqual(plan["rules"][0]["customDetailBindings"], {"HostFullName": "DeviceName"})

    def test_external_runtime_result_requires_target_output_schema(self):
        self.build()
        convert_solution(self.solution)
        results = self.solution / "provider-results.json"
        entry = {"detection": "Rule.yaml", "status": "passed", "schemaColumnCount": 3}
        results.write_text(json.dumps([entry]))
        result = record_runtime_validation(self.solution, provider="triage-mcp", results_path=results)
        self.assertEqual(result["blocked"], 1)
        entry["schema"] = [{"Name": "Other"}]
        results.write_text(json.dumps([entry]))
        result = record_runtime_validation(self.solution, provider="triage-mcp", results_path=results)
        self.assertEqual(result["invalid"], 1)
        entry["schema"] = [{"Name": "DeviceName"}]
        results.write_text(json.dumps([entry]))
        result = record_runtime_validation(self.solution, provider="triage-mcp", results_path=results)
        self.assertEqual(result["valid"], 1)

    @patch("sentinel_xdr_migration.runtime._advanced_hunting_token", return_value="test-only")
    @patch("sentinel_xdr_migration.runtime.run_advanced_hunting_query")
    def test_runtime_query_success_requires_detail_column_bindings(self, run_query, _token):
        self.build()
        convert_solution(self.solution)
        run_query.return_value = {
            "ok": True, "statusCode": 200, "rowCount": 0,
            "schema": [{"Name": "Other"}], "error": None, "errorDetails": None,
        }
        result = validate_advanced_hunting(self.solution)
        self.assertEqual(result["invalid"], 1)
        self.assertIn("HostFullName", result["results"][0]["error"])
        run_query.return_value["schema"] = [{"Name": "DeviceName"}]
        result = validate_advanced_hunting(self.solution)
        self.assertEqual(result["valid"], 1)
