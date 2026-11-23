"""DPDP-TP-002: personal data stored or sent outside India (scanner/detectors/config_files.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.config_files import regions_outside_india
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-TP-002"


def scan(folder):
    return regions_outside_india(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.confidence) for h in hits] == [
        ("deploy.env", 1, "low"),  # AWS_REGION=us-east-1
        ("main.tf", 2, "low"),  # AWS eu-west-1
        ("storage.tf", 3, "low"),  # Azure westeurope
    ]
    assert all("s.16" in h.evidence and "verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    """Mumbai, Hyderabad and Central India; `location = "checkout"` is not a region."""
    assert scan(FIXTURES / "fixed") == []


def test_no_personal_data_means_nothing_to_report(tmp_path):
    (tmp_path / "main.tf").write_text('provider "aws" {\n  region = "us-east-1"\n}\n', encoding="utf-8")
    assert scan(tmp_path) == []
