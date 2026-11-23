"""DPDP-RET-001: personal data with no erase or anonymise path (scanner/detectors/retention.py)."""

import textwrap

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.retention import no_erase_path
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-RET-001"

MODEL = """
    class Patient(db.Model):
        __tablename__ = "patients"
        id = db.Column(db.Integer, primary_key=True)
        diagnosis = db.Column(db.String)
"""


def scan(folder):
    return no_erase_path(Project.from_folder(folder, max_files=100))


def project(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def test_vulnerable_fixture():
    [hit] = scan(FIXTURES / "vulnerable")  # orders has no personal data, so only customers
    assert (hit.file, hit.line, hit.pii, hit.scope) == ("schema.sql", 1, ["email", "phone"], "line")


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_orm_model_without_delete(tmp_path):
    [hit] = scan(project(tmp_path, {"models.py": MODEL}))
    assert (hit.line, hit.pii) == (2, ["diagnosis"])


@pytest.mark.parametrize("erase", [
    "def forget(pid):\n    Patient.query.filter_by(id=pid).delete()\n",
    "def forget(pid):\n    db.session.execute(delete(Patient).where(Patient.id == pid))\n",
    "def forget(p):\n    db.session.delete(p)  # Patient\n",
    'def forget(pid):\n    db.execute("DELETE FROM patients WHERE id = ?", (pid,))\n',
])
def test_orm_and_sql_erase_paths(tmp_path, erase):
    assert scan(project(tmp_path, {"models.py": MODEL, "service.py": erase})) == []


def test_delete_in_a_sql_seed_file_does_not_count(tmp_path):
    files = {"models.py": MODEL, "seed.sql": "DELETE FROM patients;\n"}
    assert len(scan(project(tmp_path, files))) == 1
