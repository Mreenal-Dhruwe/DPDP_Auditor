"""FastAPI backend end to end (backend/main.py, backend/jobs.py), with temp folders."""

import io
import shutil
import zipfile
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend import jobs
from backend.main import create_app
from scanner.config import PROJECT_ROOT, Settings
from scanner.engine import scan_folder

SECRET = "4f9a7c2e81b64d0c9e3a5b7d1f2c8e60"  # planted in target_app/config.py


def zipped(folder) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(folder.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, f"{folder.name}/{path.relative_to(folder).as_posix()}")
    return buffer.getvalue()


def zip_of(entries: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buffer.getvalue()


@pytest.fixture
def settings(tmp_path):
    return Settings.from_env({"UPLOAD_DIR": str(tmp_path / "uploads"), "REPORT_DIR": str(tmp_path / "reports"),
                              "MAX_UPLOAD_MB": "2"})


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


def upload(client, data: bytes, name="target_app.zip"):
    return client.post("/api/scan", files={"file": (name, data, "application/zip")})


def leftovers(settings):
    return list(settings.upload_dir.iterdir()) if settings.upload_dir.exists() else []


def test_health_and_rules(client):
    health = client.get("/api/health").json()
    assert health["status"] == "ok" and health["rules"] == 28 and health["rules_checked"] >= 12
    rules = client.get("/api/rules").json()
    assert len(rules["rules"]) == 28 and "DPDP-CON-001" in rules["checked"]
    assert rules["meta"]["disclaimer"].startswith("Legal mapping is indicative")


def test_zip_upload_scan_and_downloads(client, settings):
    response = upload(client, zipped(PROJECT_ROOT / "target_app"))
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    status = client.get(f"/api/scan/{scan_id}").json()  # TestClient runs background tasks before returning
    assert (status["status"], status["step"], status["target"]) == ("done", "done", "target_app")
    assert status["steps"] == ["queued", "unpacking", "scanning", "writing reports", "done"]
    expected = scan_folder(PROJECT_ROOT / "target_app").summary.total  # same engine, scanned directly
    assert status["summary"]["total"] == expected
    report = client.get(f"/api/scan/{scan_id}/findings").json()
    assert report["target"] == "target_app" and len(report["findings"]) == expected
    assert all(f["file"] is None or f["file"].startswith("target_app/") for f in report["findings"])
    for fmt in ("json", "html", "sarif"):
        download = client.get(f"/api/scan/{scan_id}/report.{fmt}")
        assert download.status_code == 200
        assert f"dpdp-report-target_app.{fmt}" in download.headers["content-disposition"]
        assert SECRET not in download.text
    assert "Legal mapping is indicative, not legal advice." in client.get(f"/api/scan/{scan_id}/report.html").text
    assert client.get(f"/api/scan/{scan_id}/report.pdf").status_code in {200, 501}  # 501 without Pango
    assert client.get(f"/api/scan/{scan_id}/report.exe").status_code == 404
    assert leftovers(settings) == []  # the uploaded code was deleted after the scan


def test_unsafe_zips_fail_the_job_and_leave_nothing_behind(client, settings):
    scan_id = upload(client, zip_of({"../../evil.py": "x"}), "evil.zip").json()["scan_id"]
    status = client.get(f"/api/scan/{scan_id}").json()
    assert status["status"] == "failed" and "unsafe path" in status["error"]
    assert status["step"] == "unpacking"  # the step that failed
    assert client.get(f"/api/scan/{scan_id}/findings").status_code == 409
    bomb = zip_of({"zeros.bin": bytes(5 << 20)})  # 5 MB unpacked; MAX_UPLOAD_MB is 2
    scan_id = upload(client, bomb, "bomb.zip").json()["scan_id"]
    assert "more than 2 MB" in client.get(f"/api/scan/{scan_id}").json()["error"]
    assert leftovers(settings) == []


@pytest.mark.parametrize(("kwargs", "code"), [
    ({"files": {"file": ("big.zip", b"x" * (3 << 20), "application/zip")}}, 413),
    ({"files": {"file": ("notes.txt", b"hello", "text/plain")}}, 400),
    ({"files": {"file": ("fake.zip", b"not a zip", "application/zip")}}, 400),
    ({"files": {"other": ("a.zip", b"x", "application/zip")}}, 400),
    ({"content": b"hello", "headers": {"content-type": "text/plain"}}, 415),
    ({"json": {"git_url": "file:///etc/passwd"}}, 400),
    ({"json": {"git_url": "https://user:token@github.com/a/b"}}, 400),
    ({"json": {"git_url": "https://169.254.169.254/a/b"}}, 400),
    ({"json": ["not", "an", "object"]}, 400),
])
def test_bad_requests_are_refused(client, settings, kwargs, code):
    assert client.post("/api/scan", **kwargs).status_code == code
    assert leftovers(settings) == []


def test_git_scan(client, monkeypatch):
    def fake_clone(url, dest, timeout, max_bytes):  # no network in tests
        shutil.copytree(PROJECT_ROOT / "target_app_js", dest)
        return dest

    monkeypatch.setattr(jobs, "clone_git", fake_clone)
    response = client.post("/api/scan", json={"git_url": "https://github.com/acme/shop-api.git"})
    status = client.get(f"/api/scan/{response.json()['scan_id']}").json()
    assert (status["status"], status["target"], status["source"]) == ("done", "shop-api", "git")
    assert status["steps"][1] == "cloning"
    assert status["summary"]["total"] == scan_folder(PROJECT_ROOT / "target_app_js").summary.total


def test_unknown_unfinished_and_expired_scans(client, settings):
    assert client.get("/api/scan/does-not-exist").status_code == 404
    store = client.app.state.store
    pending = store.create("x", "zip")
    assert client.get(f"/api/scan/{pending.id}/report.json").status_code == 409
    scan_id = upload(client, zipped(PROJECT_ROOT / "target_app")).json()["scan_id"]
    report_dir = settings.report_dir / scan_id
    assert report_dir.is_dir()
    store.update(scan_id, created_at=jobs.now() - timedelta(days=settings.report_ttl_days + 1))
    assert client.get(f"/api/scan/{scan_id}").status_code == 404  # expired: forgotten...
    assert not report_dir.exists()  # ...and its reports deleted


def test_upload_names_become_safe_targets():
    assert jobs.safe_target("My App (v2).zip") == "My_App_v2"
    assert jobs.safe_target("..\\..\\evil.zip") == "evil"
    assert jobs.safe_target(".zip") == "upload"


def test_serves_the_built_frontend_with_client_side_routes(settings, tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<div id=root></div>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
    client = TestClient(create_app(settings, frontend_dist=dist))
    assert client.get("/").text == "<div id=root></div>"
    assert client.get("/scans/abc/findings/123").text == "<div id=root></div>"  # react-router route
    assert client.get("/assets/app.js").text == "console.log(1)"
    assert client.get("/assets/missing.js").status_code == 404  # a missing asset is not the app
    assert client.get("/api/nope").status_code == 404
    assert client.get("/api/health").json()["status"] == "ok"
