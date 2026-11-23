"""DPDP-CH-002: tracking or targeted ads possible for children (scanner/detectors/children.py)."""

from scanner.config import PROJECT_ROOT
from scanner.detectors.children import tracking_children
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-CH-002"


def scan(folder):
    return tracking_children(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.line, h.confidence) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("app.py", 10, "medium"),  # analytics.track for every new user (Segment)
        ("templates/register.html", 7, "high"),  # Meta Pixel: an ad tracker
        ("templates/register.html", 17, "high"),  # Hotjar on the page that asks for the birth date
    ]
    assert all("birth_date" in h.evidence for h in scan(FIXTURES / "vulnerable"))


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


def test_no_age_collected_means_no_finding(tmp_path):
    """s.9(3) is about children: without any age or date of birth there is nothing to report."""
    (tmp_path / "index.html").write_text(
        '<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>\n', encoding="utf-8")
    assert scan(tmp_path) == []


def test_javascript_age_gate(tmp_path):
    (tmp_path / "signup.html").write_text('<form><input name="dob" type="date"></form>\n', encoding="utf-8")
    (tmp_path / "tracking.ts").write_text(
        "import ReactGA from 'react-ga4'\n\nexport function start(user) {\n"
        "  if (isAdult(user.dob)) {\n    ReactGA.initialize('G-1')\n  }\n}\n", encoding="utf-8")
    assert scan(tmp_path) == []
    (tmp_path / "tracking.ts").write_text("import ReactGA from 'react-ga4'\nReactGA.initialize('G-1')\n", encoding="utf-8")
    [hit] = scan(tmp_path)
    assert (hit.file, hit.line, hit.confidence) == ("tracking.ts", 2, "medium")


def test_error_monitoring_is_not_tracking(tmp_path):
    (tmp_path / "app.py").write_text(
        "import sentry_sdk\n\ndef signup(form):\n    age = form['age']\n"
        "    sentry_sdk.capture_message('signup')\n", encoding="utf-8")
    assert scan(tmp_path) == []
