"""DPDP-SEC-004: hardcoded secrets (scanner/detectors/hardcoded_secrets.py)."""

import textwrap

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.hardcoded_secrets import hardcoded_secrets
from scanner.engine import scan_folder
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-004"
FIXTURE_SECRETS = ["9f8e7d6c5b4a39281706f5e4d3c2b1a0", "Sup3rS3cretPassw0rd", "Adm1n#2026!",
                   "Sup3rS3cret!2026", "Pg-Adm1n-2026"]


def scan(folder):
    return hardcoded_secrets(Project.from_folder(folder, max_files=100))


def write(tmp_path, name, text):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def test_vulnerable_fixture():
    found = [(h.file, h.line) for h in scan(FIXTURES / "vulnerable")]
    assert found == [("docker-compose.yml", 5), ("prod.env", 2), ("settings.py", 4), ("settings.py", 5),
                     ("settings.py", 9)]


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_no_fixture_secret_reaches_the_report():
    """Evidence and context of every finding are masked."""
    text = scan_folder(FIXTURES / "vulnerable").model_dump_json()
    assert "DPDP-SEC-004" in text
    assert [s for s in FIXTURE_SECRETS if s in text] == []


# Key-shaped values are built by concatenation so GitHub push protection does not flag this file.
@pytest.mark.parametrize("value", [
    "AKIA" + "Q3EXAMPLEZ7XK2PL",
    "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1gI3kM5",
    "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "rzp_" + "live_" + "Xk2Lm9Pq4Rs7Tv",
])
def test_known_key_formats_in_any_file(tmp_path, value):
    folder = write(tmp_path, "web/config.js", f'export const client = init({{ key: "{value}" }});\n')
    [hit] = scan(folder)
    assert (hit.file, hit.confidence) == ("web/config.js", "high")
    assert value not in hit.evidence


def test_private_key_and_admin_password(tmp_path):
    write(tmp_path, "deploy/key.pem", "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1c7x\n")
    write(tmp_path, "admin.py", 'ADMIN_PASSWORD = "Adm1n-Pass-2026"\n')  # "admin" contains "min"
    assert [(h.file, h.line) for h in scan(tmp_path)] == [("admin.py", 1), ("deploy/key.pem", 1)]


@pytest.mark.parametrize("code", [
    'SECRET_KEY = os.environ["SECRET_KEY"]',
    'API_KEY = "${API_KEY}"',
    'password = "changeme"',
    'token = "short"',
    'AWS_ACCESS_KEY_ID_NAME = "AWS_ACCESS_KEY_ID"',
    'reset_token_ttl = "86400seconds"',
    'error = "Wrong password or token"',
    'API_KEY = "<your-key-here>"',
])
def test_placeholders_and_non_secrets(tmp_path, code):
    assert scan(write(tmp_path, "app.py", code + "\n")) == []


def test_test_files_report_only_real_key_formats(tmp_path):
    write(tmp_path, "tests/test_login.py", 'PASSWORD = "Adm1n-Pass-2026"\n')   # throwaway test login: skipped
    write(tmp_path, "tests/test_aws.py", 'KEY = "' + "AKIA" + 'Q3EXAMPLEZ7XK2PL"\n')
    [hit] = scan(tmp_path)
    assert (hit.file, hit.confidence) == ("tests/test_aws.py", "low")


def test_translations_are_not_secrets(tmp_path):
    write(tmp_path, "i18n/ja_JP.json", '{\n  "MANDATORY_PASSWORD": "パスワードを入力してください"\n}\n')
    write(tmp_path, "web/lang.json", '{"PASSWORD_HINT": "パスワードは8文字以上"}\n')  # non-ASCII outside i18n/
    assert scan(tmp_path) == []


def test_key_named_secrets_are_found_and_plain_key_names_are_not(tmp_path):
    write(tmp_path, "config.js", """
        module.exports = {
          cryptoKey: 'a_field_encryption_key_here',   // line 2: vulnerable
          cookieSigningKey: "b7f3a9c1d5e84f20a6",       // line 3: vulnerable
          sessionKey: 'fe12ab34cd56ef78ab90',          // line 4: vulnerable
          randomKey: 'k9x2m4p7q1w8e5r3t6y0',           // line 5: any *Key holding a generated-looking value
          signingKey: process.env.SIGNING_KEY,
          primaryKey: 'createdAt',
          cacheKey: 'user-profile-cache',
          sortKey: 'created_at_desc',
          tokenType: 'Bearer',
        }
    """)
    assert sorted(h.line for h in scan(tmp_path)) == [3, 4, 5, 6]


def test_secrets_in_dev_and_test_config_are_lowered_to_medium(tmp_path):
    write(tmp_path, "config/env/production.js", "module.exports = { jwtSecret: 'prod-9f8e7d6c5b4a39281706' }\n")
    write(tmp_path, "config/env/development.js", "module.exports = { jwtSecret: 'dev-9f8e7d6c5b4a39281706' }\n")
    write(tmp_path, ".env.test", "API_TOKEN=tok-9f8e7d6c5b4a39281706\n")
    report = scan_folder(tmp_path)
    severity = {f.file: f.severity for f in report.findings if f.rule_id == "DPDP-SEC-004"}
    assert severity == {"config/env/production.js": "critical", "config/env/development.js": "medium", ".env.test": "medium"}
    lowered = next(f for f in report.findings if f.file == "config/env/development.js")
    assert "development or test file" in lowered.severity_reason and "critical" in lowered.severity_reason
