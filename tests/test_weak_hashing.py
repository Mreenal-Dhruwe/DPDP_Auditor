"""DPDP-SEC-003: weak password hashing (scanner/detectors/storage.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.storage import weak_password_hashing
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-003"


def scan(folder):
    return weak_password_hashing(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.line, h.confidence) for h in scan(FIXTURES / "vulnerable")]
    assert found == [(5, "medium"), (9, "high"), (14, "high")]  # by function name; direct; via h.update


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


@pytest.mark.parametrize(("code", "flagged"), [
    ("digest = hashlib.new('md5', pwd.encode()).hexdigest()", True),
    ("token = hashlib.sha256(os.urandom(32)).hexdigest()", False),
    ("etag = hashlib.md5(body).hexdigest()", False),
    ("same = hashlib.sha256(x).hexdigest() == user.password_hash", False),  # compares with a stored hash
])
def test_other_shapes(tmp_path, code, flagged):
    (tmp_path / "a.py").write_text("import hashlib, os\n" + code + "\n", encoding="utf-8")
    assert bool(scan(tmp_path)) is flagged
