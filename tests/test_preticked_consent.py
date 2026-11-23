"""DPDP-CON-002: pre-ticked or default-true consent (scanner/detectors/consent.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.consent import input_tags, is_pre_ticked, pre_ticked_consent
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-002"


def scan(folder):
    return pre_ticked_consent(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line) for h in scan(FIXTURES / "vulnerable")]
    assert found == [("Signup.jsx", 4), ("models.py", 8), ("models.py", 13),
                     ("templates/signup.html", 3), ("templates/signup.html", 5)]  # not "Remember me"


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


@pytest.mark.parametrize(("tag", "ticked"), [
    ('<input type="checkbox" checked>', True),
    ('<input type="checkbox" checked="checked">', True),
    ("<input type='checkbox' checked={true} />", True),
    ('<input type="checkbox" defaultChecked />', True),
    ('<input type="checkbox" checked={false} />', False),
    ('<input type="checkbox" checked={agreed} />', False),
    ('<input type="checkbox" onChange={(e) => set(e.target.checked)} />', False),
])
def test_is_pre_ticked(tag, ticked):
    assert is_pre_ticked(tag) is ticked


def test_input_tags_survive_arrow_functions():
    text = '<input type="checkbox" onChange={(e) => go(e)} checked /> after'
    [(offset, tag)] = input_tags(text)
    assert tag.endswith("checked />")
