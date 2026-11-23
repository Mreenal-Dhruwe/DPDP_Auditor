"""frontend/src/mock/report.json: valid, complete and up to date (scripts/make_mock_report.py)."""

from scanner.models import SEVERITIES, Report
from scripts.make_mock_report import OUT, render


def test_mock_is_up_to_date():
    assert OUT.is_file(), "run: python -m scripts.make_mock_report"
    assert OUT.read_text(encoding="utf-8") == render(), "out of date - run: python -m scripts.make_mock_report"


def test_mock_covers_every_severity_and_scope():
    report = Report.model_validate_json(OUT.read_text(encoding="utf-8"))
    assert all(report.summary.by_severity[s] >= 1 for s in SEVERITIES)
    assert {f.scope for f in report.findings} == {"line", "file", "project"}
    assert any(f.scope == "project" and f.file is None for f in report.findings)
    assert any(f.scope == "project" and f.file is not None for f in report.findings)


def test_mock_has_context_where_there_is_a_line():
    report = Report.model_validate_json(OUT.read_text(encoding="utf-8"))
    by_rule = {f.rule_id: f for f in report.findings}
    assert by_rule["DPDP-SEC-001"].context.start_line == 98      # line scope: 3 either side of 101
    assert by_rule["DPDP-CON-001"].context is not None            # project scope with related line
    assert by_rule["DPDP-SEC-008"].context is None                # whole file
    assert by_rule["DPDP-BR-001"].context is None                 # project scope, no location
    assert any("lend********" in line for line in by_rule["DPDP-SEC-004"].context.lines)


def test_mock_contains_no_raw_secrets(ground_truth):
    text = OUT.read_text(encoding="utf-8")
    assert [value for value in ground_truth["must_not_appear_in_report"] if value in text] == []
