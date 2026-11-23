"""The Finding / Report contract (scanner/models.py)."""

import json

import pytest
from pydantic import ValidationError

from scanner.models import DISCLAIMER, EVIDENCE_MAX_CHARS, SEVERITIES, Finding, Hit, Report

# The keys every consumer (reports, backend, frontend) relies on.
FINDING_KEYS = {
    "id", "rule_id", "title", "category", "scope", "file", "line", "evidence", "context", "pii", "confidence",
    "law", "penalty", "severity", "severity_reason", "fix",
}
REPORT_KEYS = {
    "tool", "tool_version", "rules_version", "target", "generated_at", "files_scanned",
    "disclaimer", "summary", "findings",
}


def make_finding(**changes):
    """The example finding from CLAUDE.md, with optional changes."""
    data = {
        "rule_id": "DPDP-SEC-001",
        "title": "Personal data written to logs",
        "category": "Security",
        "file": "app.py",
        "line": 7,
        "evidence": "print('New user:', em***@***, ******3210)",
        "pii": ["email", "phone"],
        "confidence": "high",
        "law": {"act": ["s.8(5)"], "rules": ["Rule 6(1)(a)"], "requirement": "Mask personal data."},
        "penalty": {"schedule_item": 1, "provision": "s.8(5) security safeguards", "cap": "Rs 250 crore"},
        "severity": "high",
        "severity_reason": "Logs are widely accessible and long-lived.",
        "fix": "Mask PII before logging",
    }
    data.update(changes)
    return Finding(**data)


def make_report(findings=(), **changes):
    data = {"rules_version": "0.1.0", "target": "target_app", "findings": list(findings)}
    data.update(changes)
    return Report(**data)


def test_contract_example_has_exactly_the_agreed_keys():
    data = json.loads(make_finding().model_dump_json())
    assert set(data) == FINDING_KEYS
    assert Finding.model_validate(data) == make_finding()


def test_id_is_stable_and_changes_with_location():
    assert make_finding().id == make_finding(evidence="other text").id
    assert make_finding().id != make_finding(line=8).id
    assert len(make_finding().id) == 12
    assert make_finding().id == "89229a868407"  # the example id in CLAUDE.md


@pytest.mark.parametrize(("location", "shown"), [
    ({}, "app.py:7"),
    ({"scope": "file", "file": "Dockerfile", "line": None}, "Dockerfile"),
    ({"scope": "project", "file": "app.py", "line": 125}, "project-wide (see app.py:125)"),
    ({"scope": "project", "file": None, "line": None}, "project-wide"),
])
def test_scope_decides_what_location_is_shown(location, shown):
    assert make_finding(**location).location == shown


@pytest.mark.parametrize("location", [
    {"scope": "line", "line": None},          # a line finding needs a line
    {"scope": "line", "file": None},          # ... and a file
    {"scope": "file"},                        # a file finding has no line (no fake line 1)
    {"scope": "file", "file": None, "line": None},
    {"scope": "project", "file": None},       # a line without a file
    {"scope": "everywhere"},
])
def test_location_must_fit_the_scope(location):
    with pytest.raises(ValidationError):
        make_finding(**location)


@pytest.mark.parametrize(("given", "stored"), [
    ("src\\app.py", "src/app.py"),
    ("./app.py", "app.py"),
    ("src//api/./users.py", "src/api/users.py"),
])
def test_file_is_stored_as_a_relative_posix_path(given, stored):
    assert make_finding(file=given).file == stored


@pytest.mark.parametrize("bad", [
    "/tmp/upload/app.py", "C:\\Temp\\upload\\app.py", "C:app.py", "../app.py",
    "src/../../etc/passwd", "", ".",
])
def test_absolute_or_escaping_paths_are_rejected(bad):
    with pytest.raises(ValidationError):
        make_finding(file=bad)


@pytest.mark.parametrize(("field", "value"), [
    ("severity", "urgent"),
    ("confidence", "certain"),
    ("rule_id", "SEC-001"),
    ("line", 0),
    ("title", "   "),
    ("law", {"act": [], "rules": [], "requirement": "x"}),
    ("law", {"act": ["Section 8(5)"], "rules": [], "requirement": "x"}),
    ("penalty", {"schedule_item": 1, "provision": "x", "cap": "250 crore"}),
])
def test_invalid_values_are_rejected(field, value):
    with pytest.raises(ValidationError):
        make_finding(**{field: value})


def test_context_must_surround_the_line():
    ok = make_finding(context={"start_line": 4, "lines": ["a", "b", "c", "  d", "e", "f", "g"]})
    assert ok.context.lines[3] == "  d"  # indentation is kept
    assert len(make_finding(context={"start_line": 1, "lines": ["x" * 500] * 7}).context.lines[0]) == 200
    for bad in ({"start_line": 20, "lines": ["x"]}, {"start_line": 1, "lines": []},
                {"start_line": 1, "lines": ["x"] * 8}):
        with pytest.raises(ValidationError):
            make_finding(context=bad)
    with pytest.raises(ValidationError):  # a whole-file finding has no line to show context around
        make_finding(scope="file", line=None, context={"start_line": 1, "lines": ["x"]})


def test_unknown_keys_are_rejected():
    with pytest.raises(ValidationError, match="severity_reson"):
        make_finding(severity_reson="typo")


def test_evidence_is_one_trimmed_line_and_capped():
    assert make_finding(evidence="  log.info(\n      email)  ").evidence == "log.info( email)"
    long = make_finding(evidence="x" * 1000).evidence
    assert len(long) == EVIDENCE_MAX_CHARS and long.endswith("...")


def test_pii_labels_are_lower_case_and_unique():
    assert make_finding(pii=["Email", "email", " phone "]).pii == ["email", "phone"]


def test_hit_is_validated_the_same_way_and_needs_a_confidence():
    hit = Hit(rule_id="DPDP-SEC-004", file="conf\\settings.py", line=3,
              evidence="KEY = 'ab****'", confidence="high")
    assert (hit.file, hit.pii) == ("conf/settings.py", [])
    with pytest.raises(ValidationError):
        Hit(rule_id="DPDP-SEC-004", file="a.py", line=3, evidence="x")


def test_empty_report_has_all_keys_and_zero_counts():
    data = json.loads(make_report().model_dump_json())
    assert set(data) == REPORT_KEYS
    assert data["summary"]["by_severity"] == dict.fromkeys(SEVERITIES, 0)
    assert data["disclaimer"] == DISCLAIMER


def test_report_sorts_drops_repeats_and_counts():
    log_leak = make_finding(severity="medium", line=20)
    open_route = make_finding(
        rule_id="DPDP-SEC-005", file="api.py", line=3, severity="critical",
        law={"act": ["s.8(5)"], "rules": ["Rule 6(1)(b)"], "requirement": "Control access."},
    )
    report = make_report([log_leak, open_route, log_leak])
    assert [f.rule_id for f in report.findings] == ["DPDP-SEC-005", "DPDP-SEC-001"]
    assert report.summary.total == 2
    assert report.summary.by_severity == {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 0}
    assert report.summary.by_category == {"Security": 2}
    assert report.summary.by_provision == {"s.8(5)": 2, "Rule 6(1)(b)": 1, "Rule 6(1)(a)": 1}


def test_report_round_trips_through_json():
    report = make_report([make_finding()])
    assert Report.model_validate_json(report.model_dump_json()) == report


def test_report_summary_cannot_be_faked():
    data = json.loads(make_report([make_finding()]).model_dump_json())
    data["summary"]["total"] = 99
    assert Report.model_validate(data).summary.total == 1


def test_report_must_keep_the_disclaimer():
    with pytest.raises(ValidationError):
        make_report(disclaimer="Trust us.")


@pytest.mark.parametrize("bad", ["/tmp/upload-1234", "C:\\Users\\dev\\AppData\\Local\\Temp\\upload-1234"])
def test_report_target_is_never_a_server_path(bad):
    with pytest.raises(ValidationError):
        make_report(target=bad)
