"""The answer keys (ground_truth.yml, ground_truth_js.yml) for the target apps. These tests
keep them honest."""

import ast

import pytest
import sqlglot

from scanner.config import PROJECT_ROOT
from scanner.detectors.javascript import GRAMMARS, _parser
from scanner.detectors.source import suffix_of
from scanner.evaluate import GroundTruth, load_ground_truth

TARGETS = [("target_app", "ground_truth.yml"), ("target_app_js", "ground_truth_js.yml")]


@pytest.fixture(scope="module", params=TARGETS, ids=[t for t, _ in TARGETS])
def target(request):
    folder, key = request.param
    return PROJECT_ROOT / folder, load_ground_truth(PROJECT_ROOT / key)


def test_ids_and_locations_are_unique(target):
    folder, gt = target
    assert gt.target == folder.name
    ids = [p.id for p in gt.planted]
    assert len(ids) == len(set(ids))
    spots = [(p.rule_id, p.file, p.line) for p in gt.planted]
    assert len(spots) == len(set(spots))


def test_every_rule_id_exists(target, catalogue):
    _, gt = target
    known = {r.id for r in catalogue.rules}
    notes = gt.compliant + gt.not_applicable + gt.out_of_scope
    used = {p.rule_id for p in gt.planted} | {n.rule_id for n in notes}
    assert used - known == set()


def test_every_rule_has_a_status(target, catalogue):
    """Planted, compliant, not applicable or out of scope, so a new rule forces a decision."""
    _, gt = target
    planted = {p.rule_id for p in gt.planted}
    compliant = {n.rule_id for n in gt.compliant}
    not_applicable = {n.rule_id for n in gt.not_applicable}
    out_of_scope = {n.rule_id for n in gt.out_of_scope}
    unaccounted = {r.id for r in catalogue.rules} - planted - compliant - not_applicable - out_of_scope
    assert unaccounted == set(), f"give these rules a status in the answer key: {sorted(unaccounted)}"
    assert not_applicable & (planted | compliant) == set()
    assert out_of_scope & (planted | compliant | not_applicable) == set()


def test_anchors_are_where_the_entries_say(target):
    folder, gt = target
    problems = []
    for p in gt.planted:
        if p.file is None:
            continue
        path = folder / p.file
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


def test_planted_secrets_really_are_in_the_target(target):
    folder, gt = target
    text = "\n".join(path.read_text(encoding="utf-8", errors="replace")
                     for path in folder.rglob("*") if path.is_file())
    assert gt.must_not_appear_in_report
    assert [value for value in gt.must_not_appear_in_report if value not in text] == []


def test_target_sources_parse(target):
    """Detectors read the targets with ast, sqlglot and tree-sitter (they never run them).
    A syntax error there would silently hide planted issues."""
    folder, _ = target
    for path in folder.rglob("*"):
        if path.suffix == ".py":
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        elif path.suffix == ".sql":
            sqlglot.parse(path.read_text(encoding="utf-8"), read="sqlite")
        elif suffix_of(path.name) in GRAMMARS:
            tree = _parser(GRAMMARS[suffix_of(path.name)]).parse(path.read_bytes())
            assert not tree.root_node.has_error, f"{path.name} does not parse"


def test_ground_truth_fixture_still_matches(ground_truth):
    assert GroundTruth.model_validate(ground_truth).target == "target_app"
