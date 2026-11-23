"""DPDP-TP-001: personal data sent to third-party SDKs (scanner/detectors/thirdparty.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.thirdparty import pii_to_third_parties
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-TP-001"


def scan(folder):
    return pii_to_third_parties(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.line, h.pii) for h in scan(FIXTURES / "vulnerable")]
    assert found == [(8, ["email", "phone"]), (9, ["email", "ip_address"])]
    assert "sent to Mixpanel" in scan(FIXTURES / "vulnerable")[0].evidence


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_only_imported_sdks_count(tmp_path):
    code = ("class Analytics:\n    def track(self, *a): ...\n\n"
            "analytics = Analytics()\nanalytics.track(user.email)\n")
    (tmp_path / "a.py").write_text(code, encoding="utf-8")
    assert scan(tmp_path) == []


def test_segment_module_calls(tmp_path):
    code = "import analytics as seg\n\nseg.identify(uid, {'email': email, 'plan': plan})\n"
    (tmp_path / "a.py").write_text(code, encoding="utf-8")
    [hit] = scan(tmp_path)
    assert hit.pii == ["email"] and "Segment" in hit.evidence
