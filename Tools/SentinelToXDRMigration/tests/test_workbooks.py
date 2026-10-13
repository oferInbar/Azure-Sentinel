from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
from uuid import uuid4

import jsonschema
import pytest

from sentinel_xdr_migration import workbooks
from sentinel_xdr_migration._workbook_core import workbook, mapping_catalog, migrate

FIXTURES = Path(__file__).parent / "fixtures/workbooks"
SCHEMA = Path(__file__).parents[1] / "schema/xdr-workbook.schema.json"


@pytest.fixture
def solution():
    root = Path.cwd() / f".workbooks-api-test-{uuid4()}" / "FixtureSolution"
    (root / "Workbooks/nested").mkdir(parents=True)
    (root / "Data").mkdir()
    (root / "Data/Solution_Fixture.json").write_text(json.dumps({"Version": "3.2.2"}))
    notebook = {
        "version": "Notebook/1.0", "fromTemplateId": str(uuid4()),
        "items": [{"type": 3, "customWidth": "50", "content": {
            "query": "DeviceEvents | summarize count() by ActionType", "queryType": 0,
            "resourceType": workbook.LA,
        }}],
    }
    (root / "Workbooks/nested/fixture.json").write_text(json.dumps(notebook))
    try:
        yield root
    finally:
        shutil.rmtree(root.parent)


def config(solution, tables=None, evidence="reviewed exact fixture source"):
    path = solution / "Workbooks/nested/fixture.json"
    raw = json.loads(path.read_text())["items"][0]["content"]["query"]
    return {"workbookResolutions": {"Workbooks/nested/fixture.json": {
        "/items/0/content/query": {"querySha256": workbook.query_hash(raw),
                                 "tables": tables or ["DeviceEvents"], "evidence": evidence}}}}


def convert(solution, settings=None, overwrite=False):
    return workbooks.convert_workbooks(
        solution, config=settings if settings is not None else config(solution),
        report_directory=solution / "Logs/run", overwrite=overwrite)


def authored(solution):
    return solution / "XDR Workbooks/nested/fixture.json"


@pytest.mark.parametrize("case", json.loads((FIXTURES / "upstream-cases.json").read_text()),
                         ids=lambda case: Path(case["path"]).stem)
def test_six_public_source_contracts(case):
    path = FIXTURES / "sources" / case["path"]
    before = path.read_bytes()
    source = json.loads(before)
    result = workbook.convert_workbook(source, tables=case["tables"])
    output, report = result["workbook"], result["report"]
    assert len(workbook.query_surfaces(source)) == case["sourceQueries"]
    assert len(workbook.query_surfaces(output)) == case["outputQueries"]
    assert report["status"] == case["status"]
    assert {p["name"] for p in report["removedParameters"]} == set(case["removed"])
    retained = {node["name"] for pointer, node in workbook.walk(output)
                if "/parameters/" in pointer and node.get("name")}
    assert set(case["retained"]) <= retained
    def items(document):
        return [(p, n["type"], n.get("name")) for p, n in workbook.walk(document)
                if "/items/" in p and "type" in n and "content" in n]
    assert items(output) == items(source)
    if case["status"] != "blocked":
        assert all(s["node"]["queryType"] == workbook.AH for s in workbook.query_surfaces(output))
        assert workbook.convert_workbook(output, tables=case["tables"])["workbook"] == output
    else:
        assert sum(i["code"] == "saved-function" for i in report["issues"]) == 2
    assert path.read_bytes() == before


@pytest.mark.parametrize("case", json.loads((FIXTURES / "upstream-cases.json").read_text()),
                         ids=lambda case: Path(case["path"]).stem)
def test_six_public_source_api_provenance_and_query_remaps(solution, case):
    shutil.rmtree(solution / "Workbooks")
    relative = "Workbooks/" + Path(case["path"]).name
    source = solution / relative
    source.parent.mkdir()
    source.write_bytes((FIXTURES / "sources" / case["path"]).read_bytes())
    before = source.read_bytes()
    source_document = json.loads(before)
    settings = {
        "workbookResolutions": {relative: {
            q["path"]: {"querySha256": workbook.query_hash(q["node"]["query"]),
                        "tables": case["tables"], "evidence": "Reviewed public-source contract"}
            for q in workbook.query_surfaces(source_document)}},
        "workbookDependencies": {relative: {
            "requiredWorkloads": [{"workload": "sentinel", "dataTypes": case["tables"]}],
            "requiredDataConnectors": [{"connectorId": "ReviewedFixtureConnector",
                                       "dataTypes": case["tables"]}]}},
    }
    result = convert(solution, settings)
    assert result["total"] == 1
    assert result["converted"] == (case["status"] != "blocked")
    output = solution / result["results"][0]["outputRelativePath"]
    document = json.loads(output.read_bytes())
    assert len(document["contentProvenance"]["conversion"]["queries"]) == case["sourceQueries"]
    assert all(q["sourceSha256"] for q in document["contentProvenance"]["conversion"]["queries"])
    assert source.read_bytes() == before
    if case["status"] != "blocked":
        jsonschema.validate(document, json.loads(SCHEMA.read_text()))
        assert workbooks.validate_workbooks(solution)["valid"] == 1
    else:
        assert workbooks.validate_workbooks(solution)["invalid"] == 1


def test_packaged_schema_is_exact_canonical_schema():
    from importlib.resources import files
    assert files("sentinel_xdr_migration._workbook_core").joinpath(
        "data/xdr-workbook.schema.json").read_bytes() == SCHEMA.read_bytes()


def test_inventory_provenance_and_stable_identity(solution):
    source = solution / "Workbooks/nested/fixture.json"
    before = source.read_bytes()
    row = workbooks.inventory_workbooks(solution)[0]
    assert row["path"] == "Workbooks/nested/fixture.json"
    assert row["sha256"] == hashlib.sha256(before).hexdigest()
    first = convert(solution)
    assert first["converted"] == 1 and first["blocked"] == 0
    content = json.loads(authored(solution).read_text())
    jsonschema.validate(content, json.loads(SCHEMA.read_text()))
    metadata = content["xdrMetadata"]
    assert metadata["contentId"] == row["identity"]
    assert metadata["contentId"] != metadata["instanceId"]
    assert metadata["version"] == "3.2.2"
    assert content["version"] == "Notebook/1.0"
    assert content["items"][0]["customWidth"] == "50"
    assert content["contentProvenance"]["requiredWorkloads"] == [
        {"workload": "mde", "dataTypes": ["DeviceEvents"]}]
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    output = authored(solution).read_bytes()
    assert convert(solution) == first
    assert authored(solution).read_bytes() == output
    assert source.read_bytes() == before
    assert not (solution / "Logs/run/manifest.json").exists()


def test_pre31_release_is_explicit_blocker_or_selected_target(solution):
    data = solution / "Data/Solution_Fixture.json"
    data.write_text('{"Version":"3.0.9"}')
    blocked = convert(solution)
    assert blocked["blocked"] == 1
    assert any(i["code"] == "release-version-required" for i in blocked["results"][0]["issues"])
    settings = config(solution)
    settings["targetVersion"] = "3.2.5"
    assert convert(solution, settings, overwrite=True)["converted"] == 1
    assert json.loads(authored(solution).read_text())["xdrMetadata"]["version"] == "3.2.5"
    assert json.loads(data.read_text())["Version"] == "3.0.9"


def test_independent_authored_workbook_keeps_31_content_floor(solution):
    assert convert(solution)["converted"] == 1
    document = json.loads(authored(solution).read_text())
    document["xdrMetadata"]["version"] = "3.1.0"
    authored(solution).write_text(json.dumps(document))
    assert workbooks.validate_workbooks(solution)["invalid"] == 0


@pytest.mark.parametrize("version", ["3.0.9", "3.1.999", "4.0.0", "3.2", "03.2.0", "3.2.0-preview"])
def test_unsupported_target_versions_reject_without_mutation(solution, version):
    settings = config(solution)
    settings["targetVersion"] = version
    before = {p.relative_to(solution): p.read_bytes() for p in solution.rglob("*") if p.is_file()}
    with pytest.raises(ValueError, match="target version"):
        convert(solution, settings)
    assert before == {p.relative_to(solution): p.read_bytes() for p in solution.rglob("*") if p.is_file()}
    assert not (solution / "XDR Workbooks").exists()
    assert not (solution / "Logs").exists()


def test_missing_reviewed_resolution_retains_candidate_and_report(solution):
    result = convert(solution, {})
    assert result["blocked"] == 1
    assert json.loads(authored(solution).read_text())["items"] == json.loads(
        (solution / "Workbooks/nested/fixture.json").read_text())["items"]
    assert workbooks.validate_workbooks(solution)["invalid"] == 1
    assert Path(result["manifestPath"]).is_file() and Path(result["reportPath"]).is_file()


def test_raw_wrapper_resolution_hash_and_stale_evidence(solution):
    path = solution / "Workbooks/nested/fixture.json"
    document = json.loads(path.read_text())
    node = document["items"][0]["content"]
    original = node["query"]
    node.update(queryType=workbook.AH, query=json.dumps({
        "__advancedHuntingSettings": True, "query": original, "selectedWorkspaceIds": ["synthetic"]}))
    path.write_text(json.dumps(document))
    settings = config(solution)
    assert convert(solution, settings)["converted"] == 1
    query = json.loads(authored(solution).read_text())["contentProvenance"]["conversion"]["queries"][0]
    assert query["sourceSha256"] == workbook.query_hash(node["query"])
    assert query["targetSha256"] == workbook.query_hash(original)
    settings["workbookResolutions"]["Workbooks/nested/fixture.json"]["/items/0/content/query"]["querySha256"] = workbook.query_hash(original)
    assert convert(solution, settings, overwrite=True)["blocked"] == 1


def test_edited_output_never_silently_overwritten(solution):
    convert(solution)
    path = authored(solution)
    path.write_text(path.read_text() + "\n")
    edited = path.read_bytes()
    result = convert(solution, overwrite=True)
    assert result["results"][0]["status"] == "conflict"
    assert path.read_bytes() == edited
    assert convert(solution, overwrite=True)["results"][0]["status"] == "conflict"


def test_changed_source_requires_current_resolution_and_explicit_overwrite(solution):
    convert(solution)
    path = solution / "Workbooks/nested/fixture.json"
    old_config = config(solution)
    document = json.loads(path.read_text())
    document["items"][0]["content"]["query"] += " | take 1"
    path.write_text(json.dumps(document))
    assert convert(solution, old_config)["results"][0]["status"] == "conflict"
    assert convert(solution, old_config, overwrite=True)["blocked"] == 1
    assert convert(solution, overwrite=True)["converted"] == 1


def test_connector_associations_are_explicit(solution):
    path = solution / "Workbooks/nested/fixture.json"
    document = json.loads(path.read_text())
    document["items"][0]["content"]["query"] = "Syslog | count"
    path.write_text(json.dumps(document))
    settings = config(solution, ["Syslog"])
    assert convert(solution, settings)["blocked"] == 1
    settings["workbookDependencies"] = {"Workbooks/nested/fixture.json": {
        "requiredDataConnectors": [{"connectorId": "Syslog", "dataTypes": ["Syslog"]}]}}
    assert convert(solution, settings, overwrite=True)["converted"] == 1
    assert workbooks.validate_workbooks(solution)["valid"] == 1
    settings["workbookDependencies"]["Workbooks/nested/fixture.json"]["requiredDataConnectors"][0]["dataTypes"] = ["SecurityEvent"]
    with pytest.raises(ValueError, match="outside reviewed"):
        convert(solution, settings, overwrite=True)


def test_selected_empty_missing_duplicate_and_unsafe_references(solution):
    convert(solution)
    data = solution / "Data/Solution_Fixture.json"
    for references in ([], ["XDR Workbooks/nested/fixture.json"]):
        data.write_text(json.dumps({"Version": "3.2.2", "XDR Workbooks": references}))
        assert workbooks.validate_workbooks(solution, selected_only=True)["total"] == len(references)
    for references in (
        ["XDR Workbooks/missing.json"], ["XDR Workbooks/../Workbooks/nested/fixture.json"],
        ["XDR Workbooks/nested/fixture.json"] * 2, ["/absolute.json"],
    ):
        data.write_text(json.dumps({"Version": "3.2.2", "XDR Workbooks": references}))
        with pytest.raises(ValueError):
            workbooks.selected_workbook_files(solution)
    data.write_text('{"Version":"3.2.2"}')
    with pytest.raises(ValueError, match="explicit"):
        workbooks.validate_workbooks(solution, selected_only=True)


def test_inventory_duplicate_identity_and_symlinks_are_rejected(solution):
    path = solution / "Workbooks/nested/fixture.json"
    duplicate = path.with_name("duplicate.json")
    duplicate.write_bytes(path.read_bytes())
    with pytest.raises(ValueError, match="Duplicate workbook identity"):
        workbooks.inventory_workbooks(solution)
    duplicate.unlink()
    duplicate.symlink_to(path)
    with pytest.raises(ValueError, match="Symlink"):
        workbooks.inventory_workbooks(solution)


def test_output_symlink_parent_and_reports_in_content_are_rejected(solution):
    (solution / "XDR Workbooks").symlink_to(solution / "Workbooks")
    with pytest.raises(ValueError, match="Symlink"):
        convert(solution)
    (solution / "XDR Workbooks").unlink()
    with pytest.raises(ValueError, match="outside"):
        workbooks.convert_workbooks(solution, report_directory=solution / "Workbooks")


@pytest.mark.parametrize("content", ["{}", "[]", "not json", '{"version":"Notebook/1.0","items":{}}'])
def test_malformed_source_rejected_before_output(solution, content):
    (solution / "Workbooks/nested/fixture.json").write_text(content)
    with pytest.raises((ValueError, json.JSONDecodeError)):
        convert(solution, {})
    assert not (solution / "XDR Workbooks").exists()


def test_stale_source_and_output_query_validation(solution):
    convert(solution)
    path = authored(solution)
    document = json.loads(path.read_text())
    document["items"][0]["content"]["query"] += " | take 2"
    path.write_text(json.dumps(document))
    assert workbooks.validate_workbooks(solution)["invalid"] == 1
    source = solution / "Workbooks/nested/fixture.json"
    source.write_bytes(source.read_bytes() + b"\n")
    assert any("stale" in error for error in workbooks.validate_workbooks(solution)["results"][0]["errors"])


def test_no_source_or_target_queries_is_valid(solution):
    path = solution / "Workbooks/nested/fixture.json"
    path.write_text('{"version":"Notebook/1.0","items":[{"type":1,"content":{"json":"text"}}]}')
    assert convert(solution, {})["converted"] == 1
    assert workbooks.validate_workbooks(solution)["valid"] == 1


def test_static_catalog_load_errors_are_not_silent(solution, monkeypatch):
    monkeypatch.setattr(migrate, "_load", lambda path: (_ for _ in ()).throw(ValueError("bad schema")))
    with pytest.raises(ValueError, match="bad schema"):
        convert(solution)
    assert not authored(solution).exists()


def test_live_resolution_is_explicitly_unsupported():
    from sentinel_xdr_migration._workbook_core import migrator
    with pytest.raises(ValueError, match="Live"):
        migrator.convert("DeviceEvents", resolve=True)


def test_fallback_identities_are_stable_without_authoritative_template(solution):
    source = solution / "Workbooks/nested/fixture.json"
    document = json.loads(source.read_bytes())
    del document["fromTemplateId"]
    source.write_text(json.dumps(document))
    first = convert(solution)
    source.write_bytes(source.read_bytes() + b"\n")
    second = convert(solution, overwrite=True)
    assert first["results"][0]["identity"] == second["results"][0]["identity"]
    assert first["results"][0]["instanceId"] == second["results"][0]["instanceId"]


def test_validation_rejects_identity_forgery_and_panel_omission(solution):
    convert(solution)
    path = authored(solution)
    document = json.loads(path.read_bytes())
    document["xdrMetadata"]["contentId"] = str(uuid4())
    path.write_text(json.dumps(document))
    assert workbooks.validate_workbooks(solution)["invalid"] == 1
    document["xdrMetadata"]["contentId"] = workbooks.inventory_workbooks(solution)[0]["identity"]
    document["items"] = []
    query = document["contentProvenance"]["conversion"]["queries"][0]
    query.update(status="removed-scope-helper", outputPath=None, targetSha256=None)
    path.write_text(json.dumps(document))
    result = workbooks.validate_workbooks(solution)
    assert result["invalid"] == 1
    assert any("proven scope" in e for e in result["results"][0]["errors"])


def test_late_overwrite_edit_is_detected_and_staging_is_cleaned(solution, monkeypatch):
    convert(solution)
    path = authored(solution)
    original = path.read_bytes()
    real_fsync = workbooks.os.fsync
    def edit_before_commit(fd):
        real_fsync(fd)
        path.write_bytes(original + b"\n")
    monkeypatch.setattr(workbooks.os, "fsync", edit_before_commit)
    source = solution / "Workbooks/nested/fixture.json"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="changed"):
        convert(solution, overwrite=True)
    assert path.read_bytes() == original + b"\n"
    assert not list(path.parent.glob("*.staged"))


@pytest.mark.parametrize("settings", [[], False, "invalid"])
def test_malformed_configuration_not_treated_as_empty(solution, settings):
    with pytest.raises(ValueError, match="configuration"):
        convert(solution, settings)


def test_missing_authored_candidates_remain_validation_failures(solution):
    result = workbooks.validate_workbooks(solution)
    assert result["total"] == 1 and result["invalid"] == 1


def test_runtime_ui_never_implied_and_offline_calls_only(solution, monkeypatch):
    import socket
    import subprocess
    def forbidden(*args, **kwargs):
        raise AssertionError("Unexpected runtime operation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    result = convert(solution)
    assert result["results"][0]["validation"] == {
        "localStructureOnly": True, "runtime": "not-run", "ui": "not-run"}
    assert result["results"][0]["gates"]
    assert workbooks.validate_workbooks(solution)["valid"] == 1
