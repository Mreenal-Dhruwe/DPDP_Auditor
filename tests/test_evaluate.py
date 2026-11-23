"""Scan target_app and compare with ground_truth.yml (scanner/evaluate.py).

test_target_app_regression grows with the project: every new detector must find all of
its planted issues in target_app and must not flag anything else.
"""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors import covered_rules
from scanner.engine import scan_folder
from scanner.evaluate import GroundTruth, Planted, detects, evaluate, main
from scanner.models import Finding

TARGET_APP = PROJECT_ROOT / "target_app"


@pytest.fixture(scope="module")
def result(ground_truth, catalogue):
    return evaluate(scan_folder(TARGET_APP, catalogue), GroundTruth.model_validate(ground_truth), covered_rules())


def test_target_app_regression(result):
    assert [f"{f.rule_id} {f.location}" for f in result.false_positives] == []
    assert [p.id for p in result.missed_with_detector] == []
    assert result.detected, "at least one planted issue should be detected"


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
