"""DPDP-SEC-008: insecure infrastructure configuration (scanner/detectors/config_files.py)."""

import pytest

from scanner.config import PROJECT_ROOT
from scanner.detectors.config_files import insecure_infrastructure
from scanner.ingest import Project

FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "DPDP-SEC-008"


def scan(folder):
    return insecure_infrastructure(Project.from_folder(folder, max_files=100))


def test_vulnerable_fixture():
    found = [(h.file, h.scope, h.line) for h in scan(FIXTURES / "vulnerable")]
    assert found == [
        ("Dockerfile", "file", None),  # USER node only in the build stage, final stage runs as root
        ("app.py", "line", 6),         # CORS(app)
        ("app.py", "line", 10),        # verify=False
        ("app.py", "line", 14),        # debug=True
        ("docker-compose.yml", "line", 4),
        ("docker-compose.yml", "line", 6),
        ("docker-compose.yml", "line", 7),
        ("storage.tf", "line", 3),
    ]


def test_fixed_fixture_is_clean():
    assert scan(FIXTURES / "fixed") == []


@pytest.mark.parametrize(("dockerfile", "flagged"), [
    ("FROM python:3.13-slim\nUSER root\n", True),
    ("FROM python:3.13-slim\nUSER 1000:1000\n", False),
    ("FROM python:3.13-slim\nRUN useradd app && \\\n    chown app /app\nUSER app\n", False),
])
def test_dockerfile_users(tmp_path, dockerfile, flagged):
    (tmp_path / "Dockerfile").write_text(dockerfile, encoding="utf-8")
    assert bool(scan(tmp_path)) is flagged


def test_fastapi_cors_wildcard(tmp_path):
    code = 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)\n'
    (tmp_path / "main.py").write_text(code, encoding="utf-8")
    [hit] = scan(tmp_path)
    assert "every website" in hit.evidence
