"""DPDP-NOT-001: personal data collected without a notice (scanner/detectors/consent.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import missing_notice
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-NOT-001"


def scan(folder):
    return missing_notice(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.pii, h.confidence) for h in hits] == [
        ("KycForm.jsx", 3, ["aadhaar", "email"], "low"),
        ("register.html", 5, ["full_name", "pan", "phone"], "low"),
    ]
    assert all("verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    """A notice paragraph or privacy link on the page; a login form (email + password) is not collection."""
    assert scan(FIXTURES / "fixed") == []
