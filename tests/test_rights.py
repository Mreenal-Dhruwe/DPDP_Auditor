"""DPDP-RT-001 to RT-003: access, correction / erasure, grievance (scanner/detectors/rights.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.rights import no_access_route, no_correction_or_erasure, no_grievance_channel
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
CHECKS = {"DPDP-RT-001": no_access_route, "DPDP-RT-002": no_correction_or_erasure, "DPDP-RT-003": no_grievance_channel}


def scan(rule, folder):
    return CHECKS[rule](Project.from_folder(folder, max_files=100))


@pytest.mark.parametrize("rule", CHECKS)
def test_vulnerable_fixture(rule):
    [hit] = scan(rule, FIXTURES / rule / "vulnerable")
    assert (hit.rule_id, hit.scope, hit.file, hit.line) == (rule, "project", "schema.sql", 1)


@pytest.mark.parametrize("rule", CHECKS)
def test_fixed_fixture_is_clean(rule):
    assert scan(rule, FIXTURES / rule / "fixed") == []


def test_correction_and_erasure_are_reported_separately():
    [hit] = scan("DPDP-RT-002", FIXTURES / "DPDP-RT-002" / "vulnerable")
    assert "correct" in hit.evidence and "erase" in hit.evidence  # a password change is not a correction


def test_no_personal_data_or_no_routes_means_nothing_to_check(tmp_path):
    (tmp_path / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.route('/health')\n"
                                     "def health():\n    return 'ok'\n", encoding="utf-8")
    assert all(scan(rule, tmp_path) == [] for rule in CHECKS)  # no personal data held
    (tmp_path / "schema.sql").write_text("CREATE TABLE users (id INT, email TEXT);\n", encoding="utf-8")
    (tmp_path / "app.py").unlink()
    assert all(scan(rule, tmp_path) == [] for rule in CHECKS)  # a schema alone is not an application


def test_mounted_express_router_counts(tmp_path):
    """Juice Shop: app.use('/dataerasure', dataErasure) - the router's own routes are '/'."""
    (tmp_path / "schema.sql").write_text("CREATE TABLE users (id INT, email TEXT);\n", encoding="utf-8")
    (tmp_path / "server.ts").write_text(
        "import dataErasure from './routes/dataErasure'\nconst app = express()\n"
        "app.post('/profile', updateProfile())\napp.use('/dataerasure', dataErasure)\n", encoding="utf-8")
    assert scan("DPDP-RT-002", tmp_path) == []


def test_a_support_route_is_a_grievance_channel(tmp_path):
    (tmp_path / "schema.sql").write_text("CREATE TABLE users (id INT, email TEXT);\n", encoding="utf-8")
    (tmp_path / "server.js").write_text("app.post('/api/support/tickets', (req, res) => res.end())\n", encoding="utf-8")
    assert scan("DPDP-RT-003", tmp_path) == []
