from copy import deepcopy
import json

import pytest

from sentinel_xdr_migration import cli, workbooks
from sentinel_xdr_migration import workbook_dependencies as dependencies
from sentinel_xdr_migration.workbook_functions import candidates
from sentinel_xdr_migration._workbook_core import workbook
from test_workbooks import solution, config, convert, authored

SOURCE = "Workbooks/nested/fixture.json"
POINTER = "/items/0/content/query"


def write_query(solution, query):
    path = solution / SOURCE
    value = json.loads(path.read_bytes())
    value["items"][0]["content"]["query"] = query
    path.write_text(json.dumps(value))


def function(solution, alias="ReviewedFunction"):
    path = solution / "Parsers/nested/function.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(f"FunctionName: {alias}\nFunctionAlias: {alias}\nFunctionQuery: Syslog | count\n")
    data_path = solution / "Data/Solution_Fixture.json"
    data = json.loads(data_path.read_bytes())
    data["Parsers"] = ["Parsers/nested/function.yaml"]
    data_path.write_text(json.dumps(data))
    return {key: candidates(solution)[0][key] for key in ("functionAlias", "sourcePath", "sourceSha256")}


def decisions(plan, *, decision="accept", tables=None, functions=None):
    return {
        "planSha256": plan["planSha256"],
        "queries": [{"workbook": row["workbook"], "path": row["path"],
                     "querySha256": row["querySha256"], "decision": decision,
                     "tables": tables or ["DeviceEvents"],
                     "workspaceFunctions": [a for a in row["workspaceFunctions"]
                                            if a not in (tables or ["DeviceEvents"])]}
                    for row in plan["queries"]],
        "workbooks": [{"path": row["path"], "decision": decision,
                       "requiredWorkloads": [{"workload": "sentinel" if tables == ["Syslog"] else "mde",
                                             "dataTypes": tables or ["DeviceEvents"]}],
                       "requiredDataConnectors": ([{"connectorId": "ReviewedConnector", "dataTypes": tables}]
                                                 if tables == ["Syslog"] else []),
                       "requiredWorkspaceFunctions": functions or []}
                      for row in plan["inventory"]],
    }


def review(solution, plan, value, output="Logs/review-1"):
    folder = solution / "Logs/inputs"
    folder.mkdir(parents=True, exist_ok=True)
    plan_path, decisions_path = folder / "plan.json", folder / "decisions.json"
    plan_path.write_text(json.dumps(plan))
    decisions_path.write_text(json.dumps(value))
    return dependencies.review_workbook_dependencies(
        solution, plan_path=plan_path, decisions_path=decisions_path,
        expected_plan_sha256=plan["planSha256"], actor="test-reviewer",
        reference="approval-42", output_directory=solution / output)


def metadata(plan):
    return {"results": [
        {"workbook": row["workbook"], "path": row["path"], "workspaceId": "approved-workspace",
         "workbookSha256": row["workbookSha256"], "querySha256": row["querySha256"],
         "status": "passed", "statusCode": 200, "partial": False,
         "bindings": {}, "renderedQuery": row["queryKql"],
         "renderedQuerySha256": workbook.query_hash(row["queryKql"]),
         "timeRange": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
         "dataSources": [{"tables": ["DeviceEvents"]}]}
        for row in plan["queries"]]}


def test_plan_is_offline_hash_bound_and_never_accepts_heuristics(solution):
    before = {str(path): path.read_bytes() for path in solution.rglob("*") if path.is_file()}
    plan = dependencies.plan_workbook_dependencies(solution)
    assert plan["queries"][0]["sourceKql"].startswith("DeviceEvents")
    assert plan["queries"][0]["proposal"]["dataTypes"] == ["DeviceEvents"]
    assert plan["queries"][0]["proposalAccepted"] is False
    assert plan["queries"][0]["staticConfidence"] == "heuristic-not-reviewed"
    assert plan["liveQueriesExecuted"] is False
    assert plan["planSha256"] == dependencies.digest({k: v for k, v in plan.items() if k != "planSha256"})
    assert before == {str(path): path.read_bytes() for path in solution.rglob("*") if path.is_file()}


def test_saved_function_lineage_static_proposal_remains_unresolved(solution):
    record = function(solution)
    write_query(solution, "let DeviceEvents = Syslog; ReviewedFunction() | count")
    plan = dependencies.plan_workbook_dependencies(solution)
    row = plan["queries"][0]
    assert row["workspaceFunctions"] == [record["functionAlias"]]
    assert row["proposalAccepted"] is False
    assert row["proposal"]["reviewRequired"] is True
    assert "Underlying function tables" in " ".join(row["proposal"]["reviewReasons"])
    assert row["functionPrerequisites"][0]["coverageWarning"]


@pytest.mark.parametrize("decision", ["accept", "change"])
def test_review_writes_supported_config_receipt_not_source_and_converts(solution, decision):
    before = (solution / SOURCE).read_bytes()
    plan = dependencies.plan_workbook_dependencies(solution)
    receipt = review(solution, plan, decisions(plan, decision=decision))
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert receipt["dependencyReviewRequired"] is False
    assert convert(solution, settings)["converted"] == 1
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    assert (solution / SOURCE).read_bytes() == before
    assert json.loads((solution / "Logs/review-1/workbook-review-receipt.json").read_bytes())["actor"] == "test-reviewer"


def test_defer_cannot_clear_dependency_review(solution):
    plan = dependencies.plan_workbook_dependencies(solution)
    receipt = review(solution, plan, decisions(plan, decision="defer"))
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert receipt["dependencyReviewRequired"] is True
    assert settings["workbookDependencies"][SOURCE]["dependencyReviewRequired"] is True
    assert convert(solution, settings)["blocked"] == 1


@pytest.mark.parametrize("failure", ["hash", "query", "unknown", "incomplete", "stale-source", "stale-parser", "malformed", "unknown-key"])
def test_review_rejects_stale_malformed_incomplete_before_output_mutation(solution, failure):
    record = function(solution)
    plan = dependencies.plan_workbook_dependencies(solution)
    value = decisions(plan)
    if failure == "hash":
        value["planSha256"] = "0" * 64
    elif failure == "query":
        value["queries"][0]["querySha256"] = "0" * 64
    elif failure == "unknown":
        value["queries"][0]["path"] = "/unknown"
    elif failure == "incomplete":
        value["queries"] = []
    elif failure == "stale-source":
        write_query(solution, "DeviceEvents | take 1")
    elif failure == "stale-parser":
        with (solution / record["sourcePath"]).open("a") as handle:
            handle.write("# source changed\n")
    elif failure == "malformed":
        value["workbooks"][0]["requiredWorkloads"] = "mde"
    else:
        value["queries"][0]["typo"] = True
    with pytest.raises(ValueError):
        review(solution, plan, value)
    assert not (solution / "Logs/review-1").exists()
    assert not authored(solution).exists()


def test_technical_gaps_survive_reviewer_accept(solution):
    write_query(solution, "workspace('elsewhere').DeviceEvents | count")
    plan = dependencies.plan_workbook_dependencies(solution)
    receipt = review(solution, plan, decisions(plan))
    assert receipt["dependencyReviewRequired"] is True
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert convert(solution, settings)["blocked"] == 1


def test_reviewed_workspace_function_preserves_calls_and_shared_contract(solution):
    record = function(solution)
    raw = "ReviewedFunction({TimeRange:start}, {TimeRange:end}) | count"
    write_query(solution, raw)
    assert convert(solution, config(solution, ["Syslog"]))["blocked"] == 1
    plan = dependencies.plan_workbook_dependencies(solution)
    review(solution, plan, decisions(plan, tables=["Syslog"], functions=[record]))
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert convert(solution, settings, overwrite=True)["converted"] == 1
    document = json.loads(authored(solution).read_bytes())
    provenance = document["contentProvenance"]
    assert document["items"][0]["content"]["query"] == raw
    assert provenance["requiredWorkspaceFunctions"] == [record]
    assert provenance["conversion"]["queries"][0]["workspaceFunctions"] == ["ReviewedFunction"]
    assert provenance["conversion"]["queries"][0]["conversion"]["resolvedTables"] == ["Syslog"]
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    # Omission cannot forge an ordinary table-only query.
    del provenance["requiredWorkspaceFunctions"]
    del provenance["conversion"]["queries"][0]["workspaceFunctions"]
    authored(solution).write_text(json.dumps(document))
    assert workbooks.validate_workbooks(solution)["invalid"] == 1


@pytest.mark.parametrize("failure", ["stale", "missing-selection", "alias", "extra", "unsafe", "malformed", "duplicate-selection"])
def test_function_prerequisite_failures_block_before_candidate_writes(solution, failure):
    record = function(solution)
    write_query(solution, "ReviewedFunction() | count")
    settings = config(solution, ["Syslog"])
    settings["workbookResolutions"][SOURCE][POINTER]["workspaceFunctions"] = ["ReviewedFunction"]
    settings["workbookDependencies"] = {SOURCE: {
        "requiredWorkspaceFunctions": [deepcopy(record)],
        "requiredWorkloads": [{"workload": "sentinel", "dataTypes": ["Syslog"]}],
        "requiredDataConnectors": []}}
    selected = settings["workbookDependencies"][SOURCE]["requiredWorkspaceFunctions"][0]
    if failure == "stale":
        selected["sourceSha256"] = "0" * 64
    elif failure == "alias":
        selected["functionAlias"] = "OtherFunction"
    elif failure in ("missing-selection", "duplicate-selection"):
        data_path = solution / "Data/Solution_Fixture.json"
        data = json.loads(data_path.read_bytes())
        data["Parsers"] = [] if failure == "missing-selection" else [record["sourcePath"]] * 2
        data_path.write_text(json.dumps(data))
    elif failure == "extra":
        settings["workbookResolutions"][SOURCE][POINTER]["workspaceFunctions"].append("Unexpected")
        assert convert(solution, settings)["blocked"] == 1
        return
    elif failure == "unsafe":
        selected["sourcePath"] = "Parsers/../Data/Solution_Fixture.json"
    else:
        selected["extra"] = True
    with pytest.raises(ValueError):
        convert(solution, settings)
    assert not authored(solution).exists()
    assert not (solution / "Logs").exists()


def test_optional_branch_removal_is_separate_requested_action_not_rewrite(solution):
    record = function(solution)
    write_query(solution, "ReviewedFunction()")
    plan = dependencies.plan_workbook_dependencies(solution)
    value = decisions(plan, tables=["Syslog"], functions=[record])
    value["queries"][0]["optionalBranches"] = [{**record, "branch": "Syslog | count", "decision": "remove-request"}]
    before = (solution / record["sourcePath"]).read_bytes()
    result = review(solution, plan, value)
    assert result["parserChangeActions"][0]["status"] == "requested-not-applied"
    assert result["dependencyReviewRequired"] is True
    assert (solution / record["sourcePath"]).read_bytes() == before


def test_import_exact_metadata_and_binding_requirements(solution):
    write_query(solution, "DeviceEvents | where Timestamp >= {TimeRange:start}")
    plan = dependencies.plan_workbook_dependencies(solution)
    imported = metadata(plan)
    entry = imported["results"][0]
    entry["bindings"] = {"TimeRange:start": "datetime(2026-01-01T00:00:00Z)"}
    entry["renderedQuery"] = plan["queries"][0]["queryKql"].replace("{TimeRange:start}", entry["bindings"]["TimeRange:start"])
    entry["renderedQuerySha256"] = workbook.query_hash(entry["renderedQuery"])
    current = dependencies.plan_workbook_dependencies(solution, workspace_id="approved-workspace", imported_results=imported)
    assert current["queries"][0]["proposal"]["method"] == "log-analytics"
    assert current["queries"][0]["proposalAccepted"] is False
    assert current["liveQueriesExecuted"] is False


@pytest.mark.parametrize("failure", ["workspace", "source", "query", "error", "partial", "status", "malformed",
                                    "incomplete", "cross-input", "binding", "rendered-hash", "time"])
def test_import_rejects_failed_stale_partial_cross_workspace_unbound_metadata(solution, failure):
    write_query(solution, "DeviceEvents | where Timestamp >= {TimeRange:start}")
    plan = dependencies.plan_workbook_dependencies(solution)
    imported = metadata(plan)
    entry = imported["results"][0]
    entry["bindings"] = {"TimeRange:start": "datetime(2026-01-01T00:00:00Z)"}
    entry["renderedQuery"] = entry["renderedQuery"].replace("{TimeRange:start}", entry["bindings"]["TimeRange:start"])
    entry["renderedQuerySha256"] = workbook.query_hash(entry["renderedQuery"])
    changes = {
        "workspace": ("workspaceId", "another-workspace"), "source": ("workbookSha256", "0" * 64),
        "query": ("querySha256", "0" * 64), "error": ("error", "failed"),
        "partial": ("partial", True), "status": ("statusCode", 403),
        "malformed": ("dataSources", "Syslog"), "binding": ("bindings", {}),
        "rendered-hash": ("renderedQuerySha256", "0" * 64),
        "time": ("timeRange", {"start": "2026-01-03", "end": "2026-01-01"}),
    }
    if failure == "incomplete":
        imported["results"] = []
    elif failure == "cross-input":
        entry["dataSources"][0]["workspaceId"] = "another-workspace"
    else:
        key, value = changes[failure]
        entry[key] = value
    with pytest.raises(ValueError):
        dependencies.plan_workbook_dependencies(solution, workspace_id="approved-workspace", imported_results=imported)
    assert not (solution / "Logs").exists()


def test_cli_pure_json_plan_and_review(solution, capsys):
    assert cli.main(["workbook-dependency-plan", "--solution", str(solution)]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert not (solution / "Logs").exists()
    folder = solution / "Logs/inputs"
    folder.mkdir(parents=True)
    (folder / "plan.json").write_text(json.dumps(plan))
    (folder / "decisions.json").write_text(json.dumps(decisions(plan)))
    assert cli.main([
        "workbook-review", "--solution", str(solution), "--plan", str(folder / "plan.json"),
        "--decisions", str(folder / "decisions.json"), "--plan-sha256", plan["planSha256"],
        "--actor", "reviewer", "--reference", "ticket", "--output-dir", str(solution / "Logs/review"),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["configPath"].endswith("conversion-config.json")


def test_review_symlink_output_and_existing_receipts_are_protected(solution):
    plan = dependencies.plan_workbook_dependencies(solution)
    target = solution / "linked"
    target.symlink_to(solution / "Data", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        review(solution, plan, decisions(plan), output="linked/review")
    review(solution, plan, decisions(plan))
    before = (solution / "Logs/review-1/workbook-review-receipt.json").read_bytes()
    with pytest.raises(ValueError, match="already exist"):
        review(solution, plan, decisions(plan))
    assert (solution / "Logs/review-1/workbook-review-receipt.json").read_bytes() == before


@pytest.mark.parametrize("query", ["_GetWatchlist('fixture') | count",
                                  "Syslog | invoke _GetWatchlist('fixture')"])
def test_watchlist_is_builtin_not_workspace_installation_prerequisite(solution, query):
    write_query(solution, query)
    plan = dependencies.plan_workbook_dependencies(solution)
    assert plan["queries"][0]["workspaceFunctions"] == []
    assert not any("No current local definition" in text for text in plan["queries"][0]["gapExplanations"])
    settings = config(solution, ["Syslog"])
    settings["workbookDependencies"] = {SOURCE: {
        "requiredWorkloads": [{"workload": "sentinel", "dataTypes": ["Syslog"]}],
        "requiredDataConnectors": []}}
    assert convert(solution, settings)["converted"] == 1
    assert json.loads(authored(solution).read_bytes())["items"][0]["content"]["query"] == query


def test_watchlist_inside_saved_definition_is_not_missing_function(solution):
    record = function(solution)
    path = solution / record["sourcePath"]
    path.write_text("FunctionName: ReviewedFunction\nFunctionQuery: _GetWatchlist('fixture') | count\n")
    assert candidates(solution)[0]["nestedFunctions"] == []


@pytest.mark.parametrize("query,aliases", [
    ("union ReviewedFunction('x','y'), OtherFunction() | count", {"ReviewedFunction", "OtherFunction"}),
    ("union kind=outer (ReviewedFunction()), (OtherFunction()) | count", {"ReviewedFunction", "OtherFunction"}),
    ("DeviceEvents | join (ReviewedFunction()) on Computer", {"ReviewedFunction"}),
    ("let local=(){ReviewedFunction()}; local()", {"ReviewedFunction"}),
    ("let ids=dynamic([1,2]); DeviceEvents | summarize max(tolong(EventCount))", set()),
    ("print x='FakeFunction()' // FakeFunction()\n", set()),
])
def test_alias_inventory_is_tabular_comment_safe_and_complete(query, aliases):
    assert workbook.opaque_functions(query) == aliases


def test_later_union_operand_cannot_be_forged_away(solution):
    record = function(solution)
    write_query(solution, "union ReviewedFunction(), UnreviewedFunction() | count")
    settings = config(solution, ["Syslog"])
    settings["workbookResolutions"][SOURCE][POINTER]["workspaceFunctions"] = ["ReviewedFunction"]
    settings["workbookDependencies"] = {SOURCE: {
        "requiredWorkspaceFunctions": [record],
        "requiredWorkloads": [{"workload": "sentinel", "dataTypes": ["Syslog"]}],
        "requiredDataConnectors": []}}
    assert convert(solution, settings)["blocked"] == 1


@pytest.mark.parametrize("query", ["ReviewedFunction() | count", "_GetWatchlist('fixture') | count"])
def test_explicit_reviewed_watchlist_lineage_is_passthrough_without_catalog_mutation(solution, query):
    record = function(solution) if query.startswith("ReviewedFunction") else None
    write_query(solution, query)
    plan = dependencies.plan_workbook_dependencies(solution)
    from sentinel_xdr_migration._workbook_core import mapping_catalog
    catalog_before = deepcopy(mapping_catalog.load_mapping_catalog())
    value = decisions(plan, tables=["Syslog"], functions=[record] if record else [])
    value["queries"][0]["tables"] = ["Syslog", "Watchlist"]
    value["workbooks"][0]["requiredWorkloads"][0]["dataTypes"] = ["Syslog"]
    result = review(solution, plan, value)
    assert result["dependencyReviewRequired"] is False
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    conversion = convert(solution, settings)
    assert conversion["converted"] == 1
    document = json.loads(authored(solution).read_bytes())
    contract = document["contentProvenance"]["conversion"]["queries"][0]["conversion"]
    assert contract["resolvedTables"] == ["Syslog", "Watchlist"]
    assert document["contentProvenance"]["conversion"]["queries"][0]["referenceInputs"] == ["Watchlist"]
    assert document["items"][0]["content"]["query"] == query
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    assert "blank-ah-selection-table-visibility" in {
        gate["code"] for gate in conversion["results"][0]["gates"]}
    assert catalog_before == mapping_catalog.load_mapping_catalog()


@pytest.mark.parametrize("mapping", [{"DeviceEvents": "DeviceEvents"}, {"Watchlist": "Syslog"},
                                    {"Unknown": "Unknown"}, ["Watchlist"]])
def test_reviewed_mapping_cannot_override_catalog_or_source_scope(solution, mapping):
    plan = dependencies.plan_workbook_dependencies(solution)
    value = decisions(plan)
    value["queries"][0]["tableMappings"] = mapping
    with pytest.raises(ValueError):
        review(solution, plan, value)
    assert not (solution / "Logs/review-1").exists()


def test_raw_watchlist_metadata_is_lineage_not_telemetry_prerequisite(solution):
    from sentinel_xdr_migration.dependencies import dependency_plan, workload_records
    raw = [{"tables": ["Syslog", "Watchlist"]}]
    proposal = dependency_plan("Syslog | join _GetWatchlist('fixture') on Computer", metadata=raw)
    assert proposal["returnedDataTypes"] == ["Syslog", "Watchlist"]
    assert proposal["sourceDataTypes"] == ["Syslog", "Watchlist"]
    assert proposal["referenceInputs"] == ["Watchlist"]
    assert proposal["dataTypes"] == proposal["targetDataTypes"] == ["Syslog"]
    assert proposal["requiredWorkloads"] == [{"workload": "sentinel", "dataTypes": ["Syslog"]}]
    assert workload_records(["Watchlist", "UnknownSource"]) == ([], ["UnknownSource"])


def test_watchlist_only_query_requires_no_telemetry_workload_or_connector(solution):
    write_query(solution, "_GetWatchlist('fixture') | count")
    plan = dependencies.plan_workbook_dependencies(solution)
    proposal = plan["queries"][0]["proposal"]
    assert proposal["referenceInputs"] == ["Watchlist"]
    assert proposal["dataTypes"] == proposal["targetDataTypes"] == []
    assert proposal["requiredWorkloads"] == proposal["requiredDataConnectors"] == []
    value = decisions(plan, tables=["Watchlist"])
    value["workbooks"][0]["requiredWorkloads"] = []
    result = review(solution, plan, value)
    assert result["dependencyReviewRequired"] is False
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert convert(solution, settings)["converted"] == 1
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    provenance = json.loads(authored(solution).read_bytes())["contentProvenance"]
    assert provenance["requiredWorkloads"] == provenance["requiredDataConnectors"] == []
    assert "requiredWorkspaceFunctions" not in provenance


@pytest.mark.parametrize("field", ["requiredWorkloads", "requiredDataConnectors"])
def test_watchlist_cannot_be_declared_as_connector_telemetry(solution, field):
    plan = dependencies.plan_workbook_dependencies(solution)
    value = decisions(plan)
    record = ({"workload": "sentinel", "dataTypes": ["Watchlist"]}
              if field == "requiredWorkloads" else {"connectorId": "Watchlist", "dataTypes": ["Watchlist"]})
    value["workbooks"][0][field] = [record]
    with pytest.raises(ValueError, match="platform reference"):
        review(solution, plan, value)
    assert not (solution / "Logs/review-1").exists()


def test_other_unknown_tables_are_not_hidden_by_platform_reference_classification(solution):
    write_query(solution, "UnknownSource | count")
    plan = dependencies.plan_workbook_dependencies(solution)
    value = decisions(plan, tables=["UnknownSource"])
    value["workbooks"][0]["requiredWorkloads"] = [{"workload": "sentinel", "dataTypes": ["UnknownSource"]}]
    result = review(solution, plan, value)
    assert result["dependencyReviewRequired"] is True
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert convert(solution, settings)["blocked"] == 1


def test_metadata_time_binding_cannot_misstate_declared_range(solution):
    write_query(solution, "DeviceEvents | where Timestamp >= {TimeRange:start}")
    plan = dependencies.plan_workbook_dependencies(solution)
    imported = metadata(plan)
    entry = imported["results"][0]
    entry["bindings"] = {"TimeRange:start": "datetime(2025-01-01T00:00:00Z)"}
    entry["renderedQuery"] = entry["renderedQuery"].replace("{TimeRange:start}", entry["bindings"]["TimeRange:start"])
    entry["renderedQuerySha256"] = workbook.query_hash(entry["renderedQuery"])
    with pytest.raises(ValueError, match="time bindings"):
        dependencies.plan_workbook_dependencies(solution, workspace_id="approved-workspace", imported_results=imported)


def test_vendored_component_manifest_hashes_are_current():
    import hashlib
    from importlib.resources import files
    root = files("sentinel_xdr_migration._workbook_core")
    manifest = json.loads(root.joinpath("import-manifest.json").read_text())
    for item in manifest["components"]:
        assert hashlib.sha256(root.joinpath(item["component"]).read_bytes()).hexdigest() == item["sha256"]


def test_connector_alternatives_are_not_cumulative_or_title_recommendations(solution):
    folder = solution / "Data Connectors"
    folder.mkdir()
    for identifier, title in (("Legacy", "Modern Agent"), ("Modern", "Older connector")):
        (folder / f"{identifier}.json").write_text(json.dumps({
            "id": identifier, "title": title, "dataTypes": [{"name": "Syslog"}]}))
    data_path = solution / "Data/Solution_Fixture.json"
    data = json.loads(data_path.read_bytes())
    data["Data Connectors"] = ["Data Connectors/Legacy.json", "Data Connectors/Modern.json"]
    data["Description"] = "Reviewed source recommendation: use Modern; legacy agent is deprecated."
    data_path.write_text(json.dumps(data))
    write_query(solution, "Syslog | count")
    plan = dependencies.plan_workbook_dependencies(solution)
    assert {record["connectorId"] for record in plan["connectorAlternatives"]} == {"Legacy", "Modern"}
    assert all(record["recommendation"] is None for record in plan["connectorAlternatives"])
    assert plan["sourceRecommendationEvidence"]["reviewRequired"] is True
    assert plan["sourceRecommendationEvidence"]["titleHeuristicsUsed"] is False
    value = decisions(plan, tables=["Syslog"])
    value["workbooks"][0]["requiredDataConnectors"] = [{"connectorId": "Modern", "dataTypes": ["Syslog"]}]
    result = review(solution, plan, value)
    assert result["dependencyReviewRequired"] is False
    settings = json.loads((solution / "Logs/review-1/conversion-config.json").read_bytes())
    assert settings["workbookDependencies"][SOURCE]["requiredDataConnectors"] == [
        {"connectorId": "Modern", "dataTypes": ["Syslog"]}]


@pytest.mark.parametrize("text", ["[]", "FunctionName: bad-name\nFunctionQuery: Syslog",
                                 "FunctionAlias: 42\nFunctionQuery: Syslog",
                                 "FunctionName: ValidName\nFunctionQuery: ''",
                                 "FunctionName: ValidName\nFunctionQuery: Syslog\nFunctionParams: malformed"])
def test_malformed_workspace_function_definition_is_not_approved(solution, text):
    record = function(solution)
    path = solution / record["sourcePath"]
    path.write_text(text)
    settings = config(solution)
    record["sourceSha256"] = workbooks._sha(path.read_bytes())
    settings["workbookDependencies"] = {SOURCE: {"requiredWorkspaceFunctions": [record]}}
    with pytest.raises(ValueError):
        convert(solution, settings)
    assert not (solution / "Logs").exists()
    assert not authored(solution).exists()


def test_externaldata_is_source_operator_not_workspace_function(solution):
    record = function(solution)
    path = solution / record["sourcePath"]
    path.write_text("FunctionName: ReviewedFunction\nFunctionQuery: externaldata(value:string)['https://example.invalid/reviewed']\n")
    current = candidates(solution)[0]
    assert current["nestedFunctions"] == []
    assert current["externalSourceWarnings"]
    assert current["nestedDiscoveryExhaustive"] is False
    assert workbook.opaque_functions("externaldata(value:string)['https://example.invalid']") == set()


def test_static_nested_union_discovery_reports_unresolved_bare_branches_not_installed_claims(solution):
    record = function(solution)
    path = solution / record["sourcePath"]
    path.write_text("FunctionName: ReviewedFunction\nFunctionQuery: union isfuzzy=true CiscoISEEvent, OtherVendorParser, Syslog\n")
    current = candidates(solution)[0]
    assert current["nestedFunctions"] == []
    assert current["unresolvedBranchCandidates"] == ["CiscoISEEvent", "OtherVendorParser"]
    assert current["nestedDiscoveryExhaustive"] is False


@pytest.mark.parametrize("query", [
    "(ReviewedFunction()) | count",
    "let x = (ReviewedFunction()); x",
    "print toscalar(ReviewedFunction() | summarize count())",
    "print ReviewedFunction()",
    "print tostring(ReviewedFunction())",
    "Syslog | extend x = ReviewedFunction()",
    "Syslog | where Computer == ReviewedFunction()",
    "Syslog | where Computer in (ReviewedFunction())",
    "print (ReviewedFunction())",
    "Syslog | where Computer in ((ReviewedFunction() | project Computer))",
    "find in (ReviewedFunction()) where * has 'x'",
    "search in (ReviewedFunction()) 'x'",
    "find in (ReviewedFunction) where * has 'x'",
    "search in (ReviewedFunction) 'x'",
    "ReviewedFunction | count",
    "(ReviewedFunction) | count",
    "let x = ReviewedFunction; x",
    "let x = (ReviewedFunction); x",
    "let x = materialize(ReviewedFunction | take 1); x",
    "let x = materialize(ReviewedFunction); x",
    "Syslog | where Computer in (ReviewedFunction | project Computer)",
    "Syslog | where Computer in ((ReviewedFunction) | project Computer)",
    "Syslog | where Computer in ( ( ReviewedFunction ) | project Computer)",
    "['ReviewedFunction']() | count",
    '["ReviewedFunction"]() | count',
    "[\n'ReviewedFunction'\n]() | count",
    "print ['ReviewedFunction']()",
    "['ReviewedFunction'] | take 10",
    "union ['ReviewedFunction']",
    "union kind=outer ['ReviewedFunction']",
    "union isfuzzy=true ['ReviewedFunction']",
    "Syslog | invoke ['ReviewedFunction']()",
    "Syslog | invoke ['ReviewedFunction']",
    "table('ReviewedFunction') | take 10",
    "table('ReviewedFunction', 'all') | take 10",
    "table('ReviewedFunction', 'hotcache') | take 10",
    "table('ReviewedFunction', 'default') | take 10",
    "totable('ReviewedFunction') | take 10",
    "totable('ReviewedFunction', 'all') | take 10",
    "let local=(){ReviewedFunction()}; local()",
    "let local=(){ReviewedFunction}; local()",
    "let local=view(){ReviewedFunction}; local()",
    "view() { ReviewedFunction }",
    "Syslog | partition by Computer { ReviewedFunction }",
    "Syslog | fork (ReviewedFunction)",
    "Syslog | fork (['ReviewedFunction'])",
    "Syslog | where Computer has ['ReviewedFunction']()",
    "Syslog | where Computer !has ['ReviewedFunction']()",
    "Syslog | where Computer contains ['ReviewedFunction']()",
    "Syslog | where Computer !contains ['ReviewedFunction']()",
    "Syslog | where Computer startswith ['ReviewedFunction']()",
    "Syslog | where Computer endswith ['ReviewedFunction']()",
    "Syslog | where Computer has_cs ['ReviewedFunction']()",
    "Syslog | where Computer has['ReviewedFunction']()",
    "Syslog | where Computer !has['ReviewedFunction']()",
    "Syslog | where Computer has['ReviewedFunction'] ()",
    "Syslog | where Computer has['ReviewedFunction']\n()",
    "Syslog | where Computer contains['ReviewedFunction']()",
    "Syslog | where Computer !contains['ReviewedFunction']()",
    "Syslog | where Computer startswith['ReviewedFunction']()",
    "Syslog | where Computer endswith['ReviewedFunction']()",
    "Syslog | where Computer has_cs['ReviewedFunction']()",
    "Syslog | distinct ['ReviewedFunction']()",
    "Syslog | distinct['ReviewedFunction']()",
    "Syslog | mv-expand ['ReviewedFunction']()",
    "Syslog | mv-expand['ReviewedFunction']()",
    "print['ReviewedFunction']()",
    "union['ReviewedFunction']",
    "union kind=outer['ReviewedFunction']",
    "union isfuzzy=true['ReviewedFunction']",
    "Syslog | invoke['ReviewedFunction']()",
    "Syslog | invoke['ReviewedFunction']",
    "Syslog | join hint.strategy=broadcast (ReviewedFunction) on Computer",
    "Syslog | join kind=inner hint.strategy=broadcast (ReviewedFunction) on Computer",
    "Syslog | join hint.strategy=shuffle (['ReviewedFunction']) on Computer",
    "Syslog | lookup kind=leftouter hint.strategy=broadcast (ReviewedFunction) on Computer",
    "let local=(){Syslog | where Computer in (ReviewedFunction())}; local()",
    "DeviceEvents | lookup kind=leftouter (ReviewedFunction()) on DeviceId",
    "DeviceEvents | lookup kind=leftouter (ReviewedFunction) on DeviceId",
    "DeviceEvents | join kind = inner (ReviewedFunction) on DeviceId",
    "/* not a KQL comment */ ReviewedFunction() | count",
    "/* ReviewedFunction() */ | count",
])
def test_saved_function_scanner_catches_bypass_forms_and_enforces_review_and_validation(solution, query):
    assert workbook.opaque_functions(query) == {"ReviewedFunction"}
    record = function(solution)
    write_query(solution, query)
    plan = dependencies.plan_workbook_dependencies(solution)
    assert plan["queries"][0]["workspaceFunctions"] == ["ReviewedFunction"]
    bad_decisions = decisions(plan, tables=["Syslog", "DeviceEvents"], functions=[])
    bad_decisions["workbooks"][0]["requiredWorkspaceFunctions"] = []
    with pytest.raises(ValueError, match="Function aliases need vetted prerequisites"):
        review(solution, plan, bad_decisions)
    good_decisions = decisions(plan, tables=["Syslog", "DeviceEvents"], functions=["ReviewedFunction"])
    good_decisions["workbooks"][0]["requiredWorkspaceFunctions"] = [record]
    good_decisions["workbooks"][0]["requiredWorkloads"] = [
        {"workload": "sentinel", "dataTypes": ["Syslog"]},
        {"workload": "mde", "dataTypes": ["DeviceEvents"]},
    ]
    good_decisions["workbooks"][0]["requiredDataConnectors"] = [
        {"connectorId": "FixtureConnector", "dataTypes": ["Syslog", "DeviceEvents"]},
    ]
    review_result = review(solution, plan, good_decisions)
    assert review_result["dependencyReviewRequired"] is False
    settings = json.loads(sorted((solution / "Logs").glob("review-*/conversion-config.json"))[-1].read_bytes())
    assert convert(solution, settings)["converted"] == 1
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    doc = json.loads(authored(solution).read_bytes())
    doc["contentProvenance"].pop("requiredWorkspaceFunctions", None)
    doc["contentProvenance"]["conversion"]["queries"][0].pop("workspaceFunctions", None)
    authored(solution).write_text(json.dumps(doc))
    validation = workbooks.validate_workbooks(solution)
    assert validation["valid"] == 0
    assert any("workspace function" in err.lower() for err in validation["results"][0]["errors"])


@pytest.mark.parametrize("query,token", [
    ("{Fn} | take 10", "{Fn}"),
    ("{Fn}() | take 10", "{Fn}"),
    ("({Fn} | project Computer)", "{Fn}"),
    ("Syslog | where Computer in ({Fn} | project Computer)", "{Fn}"),
    ("{Hidden Func}() | take 10", "{Hidden Func}"),
    ("({Hidden Func} | project Computer)", "{Hidden Func}"),
    ("let x = {Fn}; x | take 10", "{Fn}"),
    ("let x = materialize({Fn} | take 1); x", "{Fn}"),
    ("table({Fn}) | take 10", "{Fn}"),
    ("table(strcat('Le', 'ak')) | take 10", "{__unsupported_table_indirection__}"),
    ("totable(strcat('Le', 'ak')) | take 10", "{__unsupported_table_indirection__}"),
    ("Syslog | join ({Fn}) on Computer", "{Fn}"),
    ("print {Fn}()", "{Fn}"),
])
def test_parameter_built_sources_and_call_targets_fail_closed(solution, query, token):
    assert token in workbook.opaque_functions(query)
    write_query(solution, query)
    plan = dependencies.plan_workbook_dependencies(solution)
    assert token in plan["queries"][0]["workspaceFunctions"]
    bad_decisions = decisions(plan, tables=["Syslog"], functions=[])
    bad_decisions["workbooks"][0]["requiredWorkspaceFunctions"] = []
    with pytest.raises(ValueError):
        review(solution, plan, bad_decisions)
    res = workbook.convert_workbook(json.loads((solution / SOURCE).read_bytes()), tables=["Syslog"])
    assert res["report"]["status"] == "blocked"


@pytest.mark.parametrize("query", [
    "Evil_CL | take 1",
    "union Evil_CL",
    "table('Evil_CL') | take 1",
])
def test_cl_suffix_requires_explicit_reviewed_table_or_function_evidence(solution, query):
    assert workbook.opaque_functions(query) == {"Evil_CL"}
    write_query(solution, query)
    plan = dependencies.plan_workbook_dependencies(solution)
    assert plan["queries"][0]["workspaceFunctions"] == ["Evil_CL"]
    bad_decisions = decisions(plan, tables=["Syslog"], functions=[])
    bad_decisions["workbooks"][0]["requiredWorkspaceFunctions"] = []
    with pytest.raises(ValueError, match="Reviewed workspaceFunctions must match exact source aliases|Function aliases need vetted prerequisites"):
        review(solution, plan, bad_decisions)
    res_unreviewed = workbook.convert_workbook(json.loads((solution / SOURCE).read_bytes()), tables=["Syslog"])
    assert res_unreviewed["report"]["status"] == "blocked"
    # When Evil_CL is explicitly supplied as a reviewed table, bare table usage is allowed
    res_reviewed_table = workbook.convert_workbook(json.loads((solution / SOURCE).read_bytes()), tables=["Evil_CL"])
    assert res_reviewed_table["report"]["queries"][0].get("workspaceFunctions", []) == []


def test_decoy_functions_cannot_satisfy_hint_flags_or_unsupported_table_indirection(solution):
    function(solution)
    decoys = ("hint", "broadcast", "__unsupported_table_indirection__", "__unsupported_escaped_call_context__")
    for alias in decoys:
        p = solution / "Parsers" / "nested" / f"{alias}.yaml"
        p.write_text(f"FunctionName: {alias}\nFunctionAlias: {alias}\nFunctionQuery: Syslog | take 1\n")
    data_file = solution / "Data" / "Solution_Fixture.json"
    data = json.loads(data_file.read_bytes())
    data["Parsers"] = ["Parsers/nested/function.yaml"] + [f"Parsers/nested/{a}.yaml" for a in decoys]
    data_file.write_text(json.dumps(data, indent=2))
    by_alias = {c["functionAlias"]: {k: c[k] for k in ("functionAlias", "sourcePath", "sourceSha256")}
                for c in candidates(solution)}
    decoy_records = [by_alias[a] for a in decoys]
    for query in (
        "Syslog | join hint.strategy=broadcast (ReviewedFunction) on Computer",
        "Syslog | join kind=inner hint.strategy=broadcast (ReviewedFunction) on Computer",
        "Syslog | join hint.strategy=shuffle (['ReviewedFunction']) on Computer",
        "table(strcat('Reviewed', 'Function')) | take 1",
        "print bag['ReviewedFunction']()",
        "Syslog | where isnotempty(todynamic(AdditionalFields)['ReviewedFunction']())",
    ):
        write_query(solution, query)
        plan = dependencies.plan_workbook_dependencies(solution)
        bad_decisions = decisions(plan, tables=["Syslog"], functions=list(decoys))
        for q_dec in bad_decisions["queries"]:
            q_dec["workspaceFunctions"] = list(decoys)
        bad_decisions["workbooks"][0]["requiredWorkspaceFunctions"] = decoy_records
        with pytest.raises(ValueError):
            review(solution, plan, bad_decisions)
        res = workbook.convert_workbook(
            json.loads((solution / SOURCE).read_bytes()),
            tables=["Syslog"],
            allowed_workspace_functions=list(decoys),
        )
        assert res["report"]["status"] == "blocked"


@pytest.mark.parametrize("query", [
    "print bag['Leak']",
    "Syslog | extend v = todynamic(AdditionalFields)['Leak'] | where isnotempty(AdditionalFields['Leak']) and tostring(AdditionalFields['Leak']['nested']) != ''",
    "Syslog | extend ['Activity Count'] = 1 | project ['Activity Count'], [\"ResolutionTime\"] = 2 | order by ['Activity Count'] desc",
    "let LocalView = view() { Syslog }; LocalView()",
    "Syslog | partition by Computer { Syslog | count }",
    "Syslog | fork (Syslog | count)",
    "table('Syslog') | take 1",
    "table('Syslog', 'all') | take 1",
    "totable('Syslog') | take 1",
])
def test_benign_member_indexing_and_catalog_table_controls(query):
    assert workbook.opaque_functions(query) == set()

