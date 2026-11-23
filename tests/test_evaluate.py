"""Scan the target apps and compare with their answer keys (scanner/evaluate.py).

test_target_regression grows with the project: every detector must find all of its
planted issues in each target and must not flag anything else (decoys included).
"""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors import covered_rules
from scanner.engine import scan_folder
from scanner.evaluate import Planted, detects, evaluate, load_ground_truth, main
from scanner.models import Finding

TARGETS = [("target_app", "ground_truth.yml"), ("target_app_js", "ground_truth_js.yml")]


@pytest.fixture(scope="module", params=TARGETS, ids=[t for t, _ in TARGETS])
def scanned(request, catalogue):
    folder, key = request.param
    truth = load_ground_truth(PROJECT_ROOT / key)
    report = scan_folder(PROJECT_ROOT / folder, catalogue)
    return report, truth, evaluate(report, truth, covered_rules())


def test_target_regression(scanned):
    _, _, result = scanned
    assert [f"{f.rule_id} {f.location}" for f in result.false_positives] == []
    assert [p.id for p in result.missed_with_detector] == []
    assert result.detected, "at least one planted issue should be detected"


def test_no_planted_secret_reaches_the_report(scanned):
    report, truth, _ = scanned
    text = report.model_dump_json()
    assert [value for value in truth.must_not_appear_in_report if value in text] == []


def finding(catalogue, **location):
    rule = catalogue.get("DPDP-SEC-001")
    return Finding(rule_id=rule.id, title=rule.title, category=rule.category, evidence="x",
                   confidence="high", law=rule.law, penalty=catalogue.penalty_caps[rule.penalty],
                   severity=rule.severity, severity_reason=rule.severity_reason, fix=rule.fix, **location)


def planted(**location):
    return Planted(id="GT-99", rule_id="DPDP-SEC-001", clue="structure", note="n", anchor="abc", **location)


@pytest.mark.parametrize(("truth", "found", "expected"), [
    ({"file": "app.py", "line": 10}, {"file": "app.py", "line": 13}, True),     # within 3 lines
    ({"file": "app.py", "line": 10}, {"file": "app.py", "line": 14}, False),
    ({"file": "app.py", "line": 10}, {"file": "other.py", "line": 10}, False),
    ({"scope": "file", "file": "Dockerfile"}, {"file": "Dockerfile", "line": 40}, True),
    ({"scope": "project"}, {"file": "anything.py", "line": 1}, True),
])
def test_matching_follows_the_planted_scope(catalogue, truth, found, expected):
    assert detects(finding(catalogue, **found), planted(**truth)) is expected


def test_command_line_report(capsys):
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "found   GT-05  DPDP-CON-001" in out
    assert "False positives: none" in out
    assert main([str(PROJECT_ROOT / "target_app_js"), "--ground-truth", str(PROJECT_ROOT / "ground_truth_js.yml")]) == 0
    assert "out of scope" in capsys.readouterr().out
