"""DPDP-CON-006: consent request offered in one language only (scanner/detectors/consent.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import single_language_consent
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-006"


def scan(folder):
    return single_language_consent(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    """@babel/core is a JavaScript compiler, not a translation library."""
    [hit] = scan(FIXTURES / "vulnerable")
    assert (hit.file, hit.line, hit.confidence) == ("consent.html", 2, "low")
    assert "verify manually" in hit.evidence


def test_fixed_fixture_is_clean():
    """A Hindi locale file next to the same page."""
    assert scan(FIXTURES / "fixed") == []


def test_i18n_library_or_markup_or_second_language_counts(tmp_path):
    (tmp_path / "consent.html").write_text("<label>I agree to the terms</label>\n", encoding="utf-8")
    assert len(scan(tmp_path)) == 1
    (tmp_path / "package.json").write_text('{"dependencies": {"react-i18next": "^15.0.0"}}', encoding="utf-8")
    assert scan(tmp_path) == []
    (tmp_path / "package.json").unlink()
    (tmp_path / "consent.html").write_text('<label>I agree</label>\n<p lang="ta">ஒப்புக்கொள்கிறேன்</p>\n', encoding="utf-8")
    assert scan(tmp_path) == []
