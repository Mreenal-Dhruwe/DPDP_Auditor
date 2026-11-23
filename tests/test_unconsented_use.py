"""DPDP-CON-004: personal data used without checking consent (scanner/detectors/consent.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import unconsented_use
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-004"


def scan(folder):
    return unconsented_use(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line, h.confidence, h.pii) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("app.py", 13, "medium", ["email"]),  # mp.track with the email, consent never checked
        ("app.py", 14, "high", ["email"]),  # send_promo_email(email)
        ("campaign.js", 4, "medium", ["email"]),  # sendMail inside a campaign function
    ]


def test_fixed_fixture_is_clean():
    """An enclosing `if` on the consent flag, or an early return when there is no consent."""
    assert scan(FIXTURES / "fixed") == []


def test_no_consent_recorded_means_nothing_to_check(tmp_path):
    (tmp_path / "jobs.py").write_text(
        "def send_newsletter(email):\n    mailer.send_newsletter(email)\n", encoding="utf-8")
    assert scan(tmp_path) == []


def test_transactional_email_is_not_marketing(tmp_path):
    (tmp_path / "models.sql").write_text("CREATE TABLE consents (id INT, purpose TEXT);\n", encoding="utf-8")
    (tmp_path / "auth.py").write_text(
        "def reset_password(email):\n    mailer.send(email, 'Your reset link')\n", encoding="utf-8")
    assert scan(tmp_path) == []
