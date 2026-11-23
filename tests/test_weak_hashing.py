"""DPDP-SEC-003: weak password hashing (scanner/detectors/storage.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.storage import weak_password_hashing
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-003"


def scan(folder):
    return weak_password_hashing(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line, h.confidence) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("auth.js", 7, "high"),   # hash(password): helper that md5-hashes its parameter
        ("auth.js", 8, "high"),   # crypto.createHash('sha1').update(password)
        ("auth.js", 9, "high"),   # md5(user.password)
        ("auth.py", 5, "medium"),  # inside hash_password(): by function name
        ("auth.py", 9, "high"),   # direct
        ("auth.py", 14, "high"),  # via h.update
    ]
    assert "hash() hashes with md5 (auth.js:4)" in scan(FIXTURES / "vulnerable")[0].evidence


def test_juice_shop_style_helper_across_files(tmp_path):
    (tmp_path / "lib").mkdir()
    (tmp_path / "models").mkdir()
    (tmp_path / "lib" / "insecurity.ts").write_text(
        "export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')\n", encoding="utf-8")
    (tmp_path / "models" / "user.ts").write_text(
        "set (clearTextPassword: string) {\n  this.setDataValue('password', security.hash(clearTextPassword))\n}\n",
        encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line) == ("models/user.ts", 2)


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
