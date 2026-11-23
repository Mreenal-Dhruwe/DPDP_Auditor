"""DPDP-CON-001: consent can be given but not withdrawn (scanner/detectors/consent.py)."""

import textwrap

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors import DETECTORS, Detector, covered_rules, run_all
from scanner.detectors.consent import consent_withdrawal
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CON-001"


def scan(folder):
    return consent_withdrawal(Project.from_folder(folder, max_files=100))


def project_with(tmp_path, files: dict[str, str]):
    for name, code in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code), encoding="utf-8")
    return tmp_path


def test_vulnerable_fixture_is_flagged_project_wide():
    [hit] = scan(FIXTURES / "vulnerable")
    assert (hit.rule_id, hit.scope, hit.file, hit.line, hit.confidence) == (
        "DPDP-CON-001", "project", "app.py", 15, "high")
    assert "POST /consent (give_consent)" in hit.evidence


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_withdraw_route_in_another_file_counts(tmp_path):
    folder = project_with(tmp_path, {
        "api/grant.py": """
            @bp.post("/consent")
            def give_consent(): ...
        """,
        "api/revoke.py": """
            @bp.post("/consent/withdraw")
            def withdraw_consent(): ...
        """,
    })
    assert scan(folder) == []


@pytest.mark.parametrize(("grant", "withdraw"), [
    ('@router.post("/consents")\nasync def create_consent(): ...', '@router.delete("/consents/{cid}")\nasync def drop(cid): ...'),
    ('@app.route("/marketing/opt-in", methods=["POST"])\ndef opt_in(): ...', '@app.route("/marketing/opt-out", methods=["POST"])\ndef opt_out(): ...'),
    ('@app.put("/preferences/consent")\ndef set_consent(): ...', '@app.post("/unsubscribe")\ndef unsubscribe(): ...'),
])
def test_grant_and_withdraw_styles(tmp_path, grant, withdraw):
    assert len(scan(project_with(tmp_path / "a", {"app.py": grant}))) == 1
    assert scan(project_with(tmp_path / "b", {"app.py": grant + "\n\n" + withdraw})) == []


def test_weak_keywords_give_medium_confidence(tmp_path):
    [hit] = scan(project_with(tmp_path, {"app.py": '@app.post("/terms/accept")\ndef accept_terms(): ...'}))
    assert hit.confidence == "medium"


@pytest.mark.parametrize("code", [
    '@app.route("/consent")\ndef show_consent(): ...',                # GET only: viewing, not granting
    '@mock.patch("app.consent.record")\ndef helper(m): ...',          # not a web route
    'def give_consent(): ...',                                       # not a route at all
])
def test_not_a_grant_route(tmp_path, code):
    assert scan(project_with(tmp_path, {"app.py": code})) == []


def test_broken_files_and_test_files_are_skipped(tmp_path):
    folder = project_with(tmp_path, {
        "broken.py": "def oops(:\n",
        "tests/test_api.py": '@app.post("/consent")\ndef fake_consent(): ...',
    })
    assert scan(folder) == []


def test_registry_declares_real_rules_and_rejects_undeclared_hits(catalogue, monkeypatch, tmp_path):
    assert covered_rules() <= {r.id for r in catalogue.rules}
    liar = Detector("liar", ("DPDP-SEC-001",), lambda project: scan(FIXTURES / "vulnerable"))
    monkeypatch.setattr("scanner.detectors.DETECTORS", DETECTORS + [liar])
    with pytest.raises(ValueError, match="does not declare"):
        run_all(Project.from_folder(tmp_path, max_files=10))
