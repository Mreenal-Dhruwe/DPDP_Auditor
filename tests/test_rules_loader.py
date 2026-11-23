"""The rules loader (scanner/rules_loader.py), on the real file and on broken copies of it."""

import re

import pytest

from scanner.config import PROJECT_ROOT
from scanner.models import Hit
from scanner.rules_loader import RulesError, load_rules, main, parse_rules

RULES_FILE = PROJECT_ROOT / "rules" / "dpdp_rules.yml"


def test_real_rules_file_is_valid(catalogue):
    ids = [r.id for r in catalogue.rules]
    assert len(ids) == len(set(ids)) >= 28
    assert {"DPDP-CON-001", "DPDP-SEC-001"} <= set(ids)


def test_every_rule_turns_a_hit_into_a_valid_finding(catalogue):
    for rule in catalogue.rules:
        hit = Hit(rule_id=rule.id, file="app.py", line=1, evidence="example", confidence="medium")
        finding = catalogue.to_finding(hit)
        assert (finding.title, finding.severity, finding.fix) == (rule.title, rule.severity, rule.fix)
        assert finding.law == rule.law
        assert finding.penalty == catalogue.penalty_caps[rule.penalty]


def test_a_finding_gets_its_own_copy_of_the_law(catalogue):
    finding = catalogue.to_finding(
        Hit(rule_id="DPDP-SEC-001", file="a.py", line=1, evidence="x", confidence="low"))
    finding.law.act.append("s.99")
    assert "s.99" not in catalogue.get("DPDP-SEC-001").law.act


def test_unknown_rule_id_is_a_clear_error(catalogue):
    with pytest.raises(RulesError, match="DPDP-XYZ-999"):
        catalogue.get("DPDP-XYZ-999")


def _rule(data, rule_id):
    return next(r for r in data["rules"] if r["id"] == rule_id)


# name -> (how to break a fresh copy of the YAML, text the error message must contain)
BREAKAGES = {
    "duplicate id": (
        lambda d: _rule(d, "DPDP-CON-002").update(id="DPDP-CON-001"), "duplicate rule id DPDP-CON-001"),
    "unknown penalty": (
        lambda d: _rule(d, "DPDP-SEC-001").update(penalty="P9"), "DPDP-SEC-001: penalty 'P9'"),
    "bad severity": (
        lambda d: _rule(d, "DPDP-SEC-001").update(severity="urgent"), "DPDP-SEC-001 -> severity"),
    "misspelt key": (
        lambda d: _rule(d, "DPDP-SEC-001").update(severity_reson="x"), "DPDP-SEC-001 -> severity_reson"),
    "missing fix": (
        lambda d: _rule(d, "DPDP-SEC-003").pop("fix"), "DPDP-SEC-003 -> fix: Field required"),
    "bad section reference": (
        lambda d: _rule(d, "DPDP-SEC-001")["law"].update(act=["Section 8(5)"]), "DPDP-SEC-001 -> law.act.0"),
    "law with no references": (
        lambda d: _rule(d, "DPDP-RET-002")["law"].update(rules=[]), "DPDP-RET-002 -> law"),
    "unknown target": (
        lambda d: _rule(d, "DPDP-SEC-001").update(targets=["database"]), "DPDP-SEC-001 -> targets.0"),
    "critical on a Rs 50 crore rule": (
        lambda d: _rule(d, "DPDP-RT-003").update(severity="critical"), "DPDP-RT-003: 'critical' needs"),
    "broken regex": (
        lambda d: d["personal_data"]["identifiers"][0].update(pattern="[0-9"), "identifier aadhaar"),
    "disclaimer dropped": (
        lambda d: d["meta"].update(disclaimer="Trust us."), "meta.disclaimer must contain"),
}


@pytest.mark.parametrize("name", BREAKAGES)
def test_broken_rules_are_reported_by_rule_id(rules_data, name):
    break_it, expected = BREAKAGES[name]
    break_it(rules_data)
    with pytest.raises(RulesError, match=re.escape(expected)):
        parse_rules(rules_data)


def test_duplicate_yaml_keys_are_refused(tmp_path):
    text = RULES_FILE.read_text(encoding="utf-8")
    broken = text.replace("    severity: critical\n", "    severity: critical\n    severity: low\n", 1)
    assert broken != text
    path = tmp_path / "rules.yml"
    path.write_text(broken, encoding="utf-8")
    with pytest.raises(RulesError, match="duplicate key 'severity'"):
        load_rules(path)


def test_missing_file_is_a_clear_error(tmp_path):
    with pytest.raises(RulesError, match="cannot read rules file"):
        load_rules(tmp_path / "missing.yml")


def test_command_line_check(capsys, tmp_path):
    assert main([str(RULES_FILE)]) == 0
    assert capsys.readouterr().out.startswith("OK")
    assert main([str(tmp_path / "missing.yml")]) == 1
