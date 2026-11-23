"""DPDP-SEC-001: personal data written to logs (scanner/detectors/logs.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.logs import pii_in_logs
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-001"


def scan(folder):
    return pii_in_logs(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.line, h.pii) for h in scan(FIXTURES / "vulnerable")]
    assert found == [(12, ["email", "phone"]), (13, ["aadhaar"]), (19, ["request body"])]


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


@pytest.mark.parametrize(("code", "pii"), [
    ('log.info("signup %s", customer.mobile_no)', ["mobile"]),
    ('logging.warning("bad dob: " + dob)', ["dob"]),
    ('self.logger.debug("%s", {"pan": pan, "user": uid})', ["pan"]),
    ('LOG.error("%s", payload["emial"])', ["email"]),  # typo still caught (low confidence)
])
def test_logged_personal_data(tmp_path, code, pii):
    (tmp_path / "svc.py").write_text(code + "\n", encoding="utf-8")
    [hit] = scan(tmp_path)
    assert hit.pii == pii


@pytest.mark.parametrize("code", [
    'log.info("User %s logged in", row["id"])',              # internal id only
    'log.info("aadhaar verification started")',              # literal text is not data
    'log.info("hash %s", hash_phone(phone))',                 # masked before logging
    'log.info("hash stored: %s", password_hash)',             # protected value
    'cache.info(email)',                                      # not a logger
    'log.info("template %s", email_template)',                # about the field, not the data
])
def test_not_personal_data_in_logs(tmp_path, code):
    (tmp_path / "svc.py").write_text(code + "\n", encoding="utf-8")
    assert scan(tmp_path) == []
