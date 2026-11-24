"""No secret may reach a report through the context lines around a finding.

Secrets are planted in the lines next to a finding, in comments, and as a value repeated
in a trailing comment. Checked in the JSON, HTML and SARIF outputs.
"""

import json

import pytest

from scanner.engine import scan_folder
from scanner.report.html_out import render_html
from scanner.report.sarif_out import to_sarif

PLANTED = ["Rohitkumar", "Admin_123xYz", "a_secure_key_for_crypto_here", "s3cr3t-Planted-Val-99", "ghp_" + "a1B2c3D4e5" * 4]

JS = """// config for the app
const cryptoKey = "a_secure_key_for_crypto_here";
const users = [{ "firstName": "Rohitkumar", "password": "Admin_123xYz", // Admin_123xYz is the demo login
  //"password": "$2a$10$abcdefghijklmnopqrstuv", // Admin_123xYz
  "tokenSigning": "s3cr3t-Planted-Val-99" }];
// ghp_PLANTED_TOKEN
const apiToken = "ghp_PLANTED_TOKEN";
"""


@pytest.fixture()
def project(tmp_path):
    token = PLANTED[3]
    (tmp_path / "app.js").write_text(JS.replace("ghp_PLANTED_TOKEN", token), encoding="utf-8")
    # a finding in the middle of the planted lines
    (tmp_path / "server.js").write_text(
        'const cryptoKey = "a_secure_key_for_crypto_here";  // keep out of logs\n'
        '// "password": "Admin_123xYz"\n'
        "app.post('/signup', (req, res) => {\n"
        "  console.log('new user', req.body.email, req.body.phone);\n"
        "  // password Admin_123xYz, s3cr3t-Planted-Val-99\n"
        "  const sessionToken = \"s3cr3t-Planted-Val-99\";\n"
        "  res.send('ok');\n"
        "});\n"
        'const users = [{ "password": "Admin_123xYz" }];\n', encoding="utf-8")
    return tmp_path


def test_planted_secrets_do_not_leak_anywhere(project, catalogue):
    report = scan_folder(project, catalogue)
    assert report.findings, "the fixture must produce findings for this test to mean anything"
    outputs = {
        "json": json.dumps(report.model_dump(mode="json")),
        "html": render_html(report),
        "sarif": json.dumps(to_sarif(report)),
    }
    for kind, text in outputs.items():
        for secret in PLANTED:
            assert secret not in text, f"{secret!r} leaked into the {kind} report"
