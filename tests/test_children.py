"""DPDP-CH-001: child data without a parental consent flow (scanner/detectors/children.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.children import is_age_field, no_parental_consent
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CH-001"


def scan(folder):
    return no_parental_consent(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    [hit] = scan(FIXTURES / "vulnerable")
    assert (hit.scope, hit.file, hit.line) == ("project", "app.py", 10)  # not the session MAX_AGE setting
    assert "date_of_birth" in hit.evidence


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


@pytest.mark.parametrize(("name", "is_age"), [
    ("dob", True), ("date_of_birth", True), ("birthDate", True), ("age", True), ("user_age", True),
    ("max_age", False), ("page", False), ("stage", False), ("cookie_age", False), ("", False),
])
def test_is_age_field(name, is_age):
    assert is_age_field(name) is is_age


def test_form_or_schema_only(tmp_path):
    (tmp_path / "signup.html").write_text('<form>\n<input type="date" name="dob">\n</form>\n', encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line) == ("signup.html", 2)


def test_date_of_birth_alone_is_low_confidence_and_a_minor_signal_raises_it(tmp_path):
    (tmp_path / "signup.html").write_text('<form>\n<input type="date" name="dob">\n</form>\n', encoding="utf-8")
    [weak] = scan(tmp_path)
    assert weak.confidence == "low" and "verify manually" in weak.evidence
    (tmp_path / "app.py").write_text("def ok(age):\n    return age >= 18\n", encoding="utf-8")
    [strong] = scan(tmp_path)
    assert strong.confidence == "medium" and "app.py:2" in strong.evidence
    (tmp_path / "parent.py").write_text("def verify_parent(parent_email): ...\n", encoding="utf-8")
    assert scan(tmp_path) == []  # a parental consent flow: no finding
