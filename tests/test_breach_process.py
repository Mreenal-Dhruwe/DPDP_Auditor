"""DPDP-BR-001: no breach notification mechanism (scanner/detectors/rights.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.rights import no_breach_process
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-BR-001"


def scan(folder):
    return no_breach_process(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    [hit] = scan(FIXTURES / "vulnerable")
    assert (hit.scope, hit.file, hit.line, hit.confidence) == ("project", "schema.sql", 1, "low")
    assert "verify manually" in hit.evidence


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_an_alerting_hook_or_runbook_counts(tmp_path):
    for name in ("schema.sql", "app.py"):
        (tmp_path / name).write_text((FIXTURES / "vulnerable" / name).read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "alerts.yml").write_text("receivers:\n  - name: security\n    pagerduty_configs: []\n", encoding="utf-8")
    assert scan(tmp_path) == []
