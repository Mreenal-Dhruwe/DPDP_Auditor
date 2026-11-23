"""DPDP-CON-003: no evidence of consent stored (scanner/detectors/consent.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import consent_evidence
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-003"


def scan(folder):
    return consent_evidence(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    hits = scan(FIXTURES / "vulnerable")
    assert [(h.file, h.line) for h in hits] == [
        ("models.js", 5),  # Sequelize consent model with timestamps: false and no notice version
        ("schema.sql", 1),  # consent table with only a boolean
        ("schema.sql", 10),  # customers.marketing_consent flag with no time
    ]
    assert "when it was given or the purpose" in hits[1].evidence


def test_fixed_fixture_is_clean():
    """Purpose + notice version + granted_at; a matching *_at column; Sequelize's own createdAt."""
    assert scan(FIXTURES / "fixed") == []


def test_purpose_without_time_is_still_reported(tmp_path):
    (tmp_path / "schema.sql").write_text("CREATE TABLE consents (\n  user_id INT,\n  purpose TEXT\n);\n", encoding="utf-8")
    [hit] = scan(tmp_path)
    assert "when it was given" in hit.evidence and "purpose" not in hit.evidence.split("record")[1]
