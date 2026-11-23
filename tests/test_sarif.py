"""SARIF 2.1.0 output (scanner/report/sarif_out.py)."""

import json

import pytest

from scanner.cli import main
from scanner.config import PROJECT_ROOT
from scanner.engine import scan_folder
from scanner.report.sarif_out import to_sarif


@pytest.fixture(scope="module")
def report(catalogue):
    return scan_folder(PROJECT_ROOT / "target_app", catalogue)


@pytest.fixture(scope="module")
def sarif(report, catalogue):
    return to_sarif(report, catalogue)


def test_document_shape(sarif, catalogue):
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    [run] = sarif["runs"]
    driver = run["tool"]["driver"]
    assert [r["id"] for r in driver["rules"]] == [r.id for r in catalogue.rules]
    for rule in driver["rules"]:
        assert rule["shortDescription"]["text"] and rule["help"]["text"]
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert float(rule["properties"]["security-severity"]) > 0
        tags = rule["properties"]["tags"]
        assert len(tags) == len(set(tags))  # the SARIF schema requires unique tags
    assert run["properties"]["disclaimer"].startswith("Legal mapping is indicative, not legal advice.")


def test_one_result_per_finding_with_location_and_fingerprint(sarif, report):
    results = sarif["runs"][0]["results"]
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]
    assert len(results) == len(report.findings)
    for result, finding in zip(results, report.findings):
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"] == finding.rule_id
        assert result["partialFingerprints"]["dpdpFindingId/v1"] == finding.id
        location = result["locations"][0]["physicalLocation"]
        assert location["artifactLocation"]["uri"] == finding.file
        assert not location["artifactLocation"]["uri"].startswith(("/", "C:"))
        if finding.line is None:
            assert "region" not in location  # whole-file finding (Dockerfile)
        else:
            assert location["region"]["startLine"] == finding.line
    levels = {r["properties"]["severity"]: r["level"] for r in results}
    assert levels == {"critical": "error", "high": "error", "medium": "warning"}


def test_project_wide_finding_without_file_has_no_location(catalogue):
    from scanner.models import Hit, Report
    finding = catalogue.to_finding(Hit(rule_id="DPDP-BR-001", scope="project", evidence="none", confidence="low"))
    [result] = to_sarif(Report(rules_version="0.1.0", target="x", findings=[finding]), catalogue)["runs"][0]["results"]
    assert "locations" not in result and result["level"] == "warning"


def test_cli_writes_all_three_formats_and_no_secret_leaks(tmp_path):
    assert main([str(PROJECT_ROOT / "target_app"), "--out", str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.html", "report.json", "report.sarif"]
    for path in tmp_path.iterdir():
        assert "4f9a7c2e81b64d0c9e3a5b7d1f2c8e60" not in path.read_text(encoding="utf-8")
    json.loads((tmp_path / "report.sarif").read_text(encoding="utf-8"))
    assert main([str(PROJECT_ROOT / "target_app"), "--out", str(tmp_path / "j"), "--formats", "json"]) == 0
    assert [p.name for p in (tmp_path / "j").iterdir()] == ["report.json"]
