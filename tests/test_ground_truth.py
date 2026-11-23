"""ground_truth.yml is the answer key for target_app/. These tests keep it honest."""

import ast

import pytest
import sqlglot

from scanner.config import PROJECT_ROOT
from scanner.evaluate import GroundTruth

TARGET_APP = PROJECT_ROOT / "target_app"


@pytest.fixture(scope="module")
def gt(ground_truth):
    return GroundTruth.model_validate(ground_truth)


def test_ids_and_locations_are_unique(gt):
    assert gt.target == "target_app"
    ids = [p.id for p in gt.planted]
    assert len(ids) == len(set(ids))
    spots = [(p.rule_id, p.file, p.line) for p in gt.planted]
    assert len(spots) == len(set(spots))


def test_every_rule_id_exists(gt, catalogue):
    known = {r.id for r in catalogue.rules}
    used = {p.rule_id for p in gt.planted} | {n.rule_id for n in gt.compliant + gt.not_applicable}
    assert used - known == set()


def test_every_rule_has_a_status(gt, catalogue):
    """Planted, deliberately compliant or not applicable, so a new rule forces a decision."""
    planted = {p.rule_id for p in gt.planted}
    compliant = {n.rule_id for n in gt.compliant}
    not_applicable = {n.rule_id for n in gt.not_applicable}
    unaccounted = {r.id for r in catalogue.rules} - planted - compliant - not_applicable
    assert unaccounted == set(), f"give these rules a status in ground_truth.yml: {sorted(unaccounted)}"
    assert not_applicable & (planted | compliant) == set()


def test_anchors_are_where_the_entries_say(gt):
    problems = []
    for p in gt.planted:
        if p.file is None:
            continue
        path = TARGET_APP / p.file
        if not path.is_file():
            problems.append(f"{p.id}: {p.file} does not exist")
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        found = [n for n, text in enumerate(lines, 1) if p.anchor in text]
        if p.line is None and not found:
            problems.append(f"{p.id}: {p.anchor!r} is not in {p.file}")
        elif p.line is not None and p.line not in found:
            problems.append(f"{p.id}: {p.anchor!r} is not on {p.file}:{p.line} (found on lines {found})")
    assert problems == [], "\n".join(problems)


def test_planted_secrets_really_are_in_target_app(gt):
    text = "\n".join(path.read_text(encoding="utf-8", errors="replace")
                     for path in TARGET_APP.rglob("*") if path.is_file())
    assert [value for value in gt.must_not_appear_in_report if value not in text] == []


def test_target_app_sources_parse():
    """Detectors read target_app with ast and sqlglot (they never run it). A syntax error
    there would silently hide planted issues."""
    for path in TARGET_APP.rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for path in TARGET_APP.rglob("*.sql"):
        sqlglot.parse(path.read_text(encoding="utf-8"), read="sqlite")
