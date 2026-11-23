"""DPDP-SEC-002: plaintext sensitive columns (scanner/detectors/storage.py, schemas.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.schemas import sql_tables
from scanner.detectors.storage import plaintext_sensitive_columns
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-002"


def scan(folder):
    return plaintext_sensitive_columns(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line, h.pii) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("models.py", 10, ["passport"]),
        ("models.py", 11, ["diagnosis"]),
        ("schema.sql", 5, ["aadhaar"]),
        ("schema.sql", 6, ["pan"]),
        ("schema.sql", 7, ["password"]),
    ]


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_sql_parser_handles_one_line_tables_and_comments():
    sql = "-- users (old)\ncreate table if not exists `app`.`users` (id int, email text /* , pan text */, pan_no varchar(10))"
    [table] = sql_tables(sql, "db.sql")
    assert (table.name, table.line) == ("users", 2)
    assert [(c.name, c.type, c.line) for c in table.columns] == [
        ("id", "INT", 2), ("email", "TEXT", 2), ("pan_no", "VARCHAR", 2)]


def test_create_table_inside_python_strings(tmp_path):
    (tmp_path / "db.py").write_text(
        'import sqlite3\n\nSCHEMA = """\nCREATE TABLE kyc (\n    id INTEGER,\n    aadhaar TEXT\n)\n"""\n',
        encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line, hit.pii) == ("db.py", 6, ["aadhaar"])
