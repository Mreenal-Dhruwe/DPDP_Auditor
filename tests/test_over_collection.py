"""DPDP-CON-005: over-collection beyond the stated purpose (scanner/detectors/consent.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import over_collection
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-005"


def scan(folder):
    return over_collection(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line, h.confidence) for h in hits] == [
        ("android/AndroidManifest.xml", 4, "low"),  # READ_CONTACTS, no contacts API in the code
        ("templates/signup.html", 4, "low"),  # dob is asked for, never read or stored
    ]
    assert "contacts" in hits[0].evidence and "'dob'" in hits[1].evidence
    assert all("verify manually" in h.evidence for h in hits)


def test_fixed_fixture_is_clean():
    """Every field is read by the handler; the location permission is used (LocationManager)."""
    assert scan(FIXTURES / "fixed") == []


def test_a_field_stored_as_a_column_is_used(tmp_path):
    (tmp_path / "form.html").write_text('<form><input name="pan_number"></form>\n', encoding="utf-8")
    assert len(scan(tmp_path)) == 1
    (tmp_path / "schema.sql").write_text("CREATE TABLE kyc (id INT, pan_number TEXT);\n", encoding="utf-8")
    assert scan(tmp_path) == []
