"""DPDP-SEC-007: personal-data reads with no audit log (scanner/detectors/logs.py)."""

import shutil

from scanner.config import PROJECT_ROOT
from scanner.detectors.logs import unaudited_reads
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-007"
SCHEMA = "CREATE TABLE customers (\n  id INTEGER,\n  name TEXT,\n  email TEXT\n);\n"


def scan(folder):
    return unaudited_reads(Project.from_folder(folder, max_files=100))


def with_schema(src, tmp_path):
    shutil.copytree(src, tmp_path / "app")
    (tmp_path / "app" / "schema.sql").write_text(SCHEMA, encoding="utf-8")
    return tmp_path / "app"


def test_vulnerable_fixture(tmp_path):
    found = [(h.file, h.line, h.pii) for h in scan(with_schema(FIXTURES / "vulnerable", tmp_path))]
    assert found == [
        ("app.py", 12, ["email"]),  # SELECT name, email - no log call
        ("server.js", 8, ["phone"]),  # Member.findByPk - no logger call
    ]


def test_fixed_fixture_is_clean(tmp_path):
    """A same-file audit helper (Python) and a logger.info in the handler (Express)."""
    assert scan(with_schema(FIXTURES / "fixed", tmp_path)) == []


def test_request_logging_middleware_covers_every_route(tmp_path):
    app = with_schema(FIXTURES / "vulnerable", tmp_path)
    server = app / "server.js"
    server.write_text(server.read_text(encoding="utf-8").replace(
        "const app = express()\n", "const app = express()\napp.use(require('morgan')('combined'))\n"), encoding="utf-8")
    assert scan(app) == []


def test_no_logger_set_up_means_nothing_to_check(tmp_path):
    (tmp_path / "schema.sql").write_text(SCHEMA, encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/c')\ndef c():\n"
        "    return db.execute('SELECT email FROM customers').fetchall()\n", encoding="utf-8")
    assert scan(tmp_path) == []
