"""DPDP-SEC-009: no backup configured for personal-data stores (scanner/detectors/config_files.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.config_files import missing_backups
from scanner.ingest import Project
from scanner.rules_loader import load_rules
from scanner.config import get_settings

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-009"


def scan(folder):
    return missing_backups(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.confidence) for h in hits] == [
        ("docker-compose.yml", 5, "low"),  # postgres, nothing backs it up
        ("rds.tf", 1, "low"),  # no backup_retention_period
        ("rds.tf", 6, "low"),  # Cloud SQL without backup_configuration
    ]
    assert all("verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_reported_as_info():
    """Backups usually live outside the repository: the rules file rates this rule info."""
    assert load_rules(get_settings().rules_file).get("DPDP-SEC-009").severity == "info"
