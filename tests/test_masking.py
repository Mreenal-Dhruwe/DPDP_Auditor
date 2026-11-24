"""Masking of secrets and personal data in evidence (scanner/masking.py)."""

import pytest

from scanner.masking import MASK, mask_evidence, mask_secret
from scanner.models import Hit


@pytest.fixture(scope="module")
def ids(catalogue):
    return catalogue.personal_data.identifiers


@pytest.mark.parametrize(("secret", "masked"), [
    ("sk_live_abcdef1234567890", "sk_live_ab" + MASK),
    ("lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60", "lend" + MASK),
    ("admin@123", MASK),            # short: nothing kept
    ("", ""),
    ("lend" + MASK, "lend" + MASK),  # already masked: unchanged
])
def test_mask_secret(secret, masked):
    assert mask_secret(secret) == masked


@pytest.mark.parametrize(("evidence", "masked"), [
    ('SECRET_KEY = "lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60"', 'SECRET_KEY = "lend' + MASK + '"'),
    ("{\"db_password\": 'hunter2hunter2'}", "{\"db_password\": '" + MASK + "'}"),
    ("DB_PASSWORD=admin123", "DB_PASSWORD=" + MASK),
    ("POSTGRES_PASSWORD: admin123", "POSTGRES_PASSWORD: " + MASK),
    ("print('New user:', 'emma.r@example.com', '9876543210')", "print('New user:', 'em***@***', '******3210')"),
    ("call +91 9876543210 now", "call +91 ******3210 now"),
    ("aadhaar = '2345 6789 0123'", "aadhaar = 'XXXX XXXX 0123'"),
    ("pan: ABCDE1234F", "pan: ******234F"),
    ("pay to ravi.k@okhdfc", "pay to ra***@okhdfc"),
])
def test_mask_evidence_hides_secrets_and_personal_data(ids, evidence, masked):
    assert mask_evidence(evidence, ids) == masked


@pytest.mark.parametrize("code", [
    'log.info("New signup: %s, %s, aadhaar %s", email, phone, aadhaar)',
    'app.config["SECRET_KEY"] = config.SECRET_KEY',
    'MIXPANEL_TOKEN = os.environ.get("MIXPANEL_TOKEN", "")',
    "IFSC code HDFC0001234 is a bank branch, not a person",
    "@app.route(\"/consent\", methods=[\"POST\"])",
])
def test_ordinary_code_is_left_alone(ids, code):
    assert mask_evidence(code, ids) == code


def test_masking_is_idempotent(ids):
    once = mask_evidence("SECRET_KEY = 'lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60' # a@b.com 9876543210", ids)
    assert mask_evidence(once, ids) == once


def test_to_finding_always_masks(catalogue):
    hit = Hit(rule_id="DPDP-SEC-004", file="config.py", line=3, confidence="high",
              evidence='SECRET_KEY = "lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60"')
    assert "4f9a7c2e" not in catalogue.to_finding(hit).evidence


# --- context lines -------------------------------------------------------------------
# Key-shaped test values are built by concatenation so that GitHub push protection does
# not mistake this file for a real leak.
AWS_KEY = "AKIA" + "Q3EXAMPLEZ7XK2PL"
KEY_BODY = "MIIEowIBAAKCAQEA1c7x9z5Pad7OejecsQ0bu3aumIaQUyp0dRA0Y8i4N8XKPnVHvPuy"
SOURCE = [
    "import os",                                                              # 1
    'DB_URL = "postgres://app:Sup3rS3cretPassw0rd@db:5432/app"',              # 2
    f'AWS_KEY = "{AWS_KEY}"',                                                 # 3
    'SECRET_KEY = "lending-demo-4f9a7c2e81b64d0c9e3a5b7d1f2c8e60"',           # 4  <- the finding
    'ADMIN = {"email": "ravi.kumar@example.com", "phone": "+91 9876543210"}', # 5
    "-----BEGIN " + "RSA PRIVATE KEY-----",                                   # 6
    KEY_BODY,                                                                 # 7
    "x = 1",                                                                  # 8
]
RAW_VALUES = ["Sup3rS3cretPassw0rd", AWS_KEY, "4f9a7c2e81b64d0c9e3a5b7d1f2c8e60",
              "ravi.kumar@example.com", "9876543210", KEY_BODY]


def make_hit(**location):
    data = {"rule_id": "DPDP-SEC-004", "file": "settings.py", "line": 4, "confidence": "high",
            "evidence": SOURCE[3]}
    data.update(location)
    return Hit(**data)


def test_every_context_line_is_masked(catalogue):
    finding = catalogue.to_finding(make_hit(), SOURCE)
    assert finding.context.start_line == 1
    assert len(finding.context.lines) == 7  # lines 1-7: three either side of line 4
    text = "\n".join(finding.context.lines) + finding.evidence
    assert [value for value in RAW_VALUES if value in text] == []
    assert finding.context.lines[0] == "import os"  # ordinary code is left alone


def test_context_is_masked_before_it_is_cut(catalogue):
    """A secret near the 200-character cut must not survive as an unterminated fragment."""
    padding = "# " + "padding " * 22
    long_line = padding + 'api_token = "abcd1234efgh5678ijkl9012mnop3456"'
    finding = catalogue.to_finding(make_hit(file="a.py", line=1, evidence=long_line), [long_line])
    [shown] = finding.context.lines
    assert len(shown) <= 200
    assert "efgh5678" not in shown and "efgh5678" not in finding.evidence


@pytest.mark.parametrize(("location", "has_context"), [
    ({}, True),                                                          # line scope
    ({"scope": "file", "line": None}, False),                            # whole file: none
    ({"scope": "project"}, True),                                        # project, related line
    ({"scope": "project", "file": None, "line": None}, False),           # project, no location
    ({"line": 99}, False),                                               # line beyond the file
])
def test_context_follows_the_scope(catalogue, location, has_context):
    finding = catalogue.to_finding(make_hit(**location), SOURCE)
    assert (finding.context is not None) == has_context


@pytest.mark.parametrize(("line", "masked"), [
    ('"firstName": "John",', '"firstName": "J' + MASK + '",'),
    ("address = 'Flat 4, MG Road'", "address = 'F" + MASK + "'"),
    ('"userName": "admin",', '"userName": "admin",'),   # not personal data
    ('placeholder: "Enter address"', 'placeholder: "Enter address"'),  # a UI word next to the name, not the data name
])
def test_quoted_values_of_personal_fields_are_masked(line, masked):
    from scanner.masking import mask_pii_literals
    from scanner.pii import default_matcher
    assert mask_pii_literals(line, default_matcher()) == masked
