"""Short-lived scans: TTL expiry, token-scoped delete, saved samples (backend/jobs.py, main.py)."""

import os
import time
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from scanner.config import PROJECT_ROOT, Settings
from tests.test_backend import upload, zipped

TARGET = zipped(PROJECT_ROOT / "target_app")


def make_settings(tmp_path, ttl="30"):
    return Settings.from_env({"UPLOAD_DIR": str(tmp_path / "uploads"), "REPORT_DIR": str(tmp_path / "reports"),
                              "SCAN_TTL_MINUTES": ttl, "MAX_UPLOAD_MB": "2"})


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


def start(client):
    body = upload(client, TARGET).json()
    return body["scan_id"], body["delete_token"]


def test_default_ttl_is_thirty_minutes():
    assert Settings.from_env({}).scan_ttl_minutes == 30
    assert Settings.from_env({"SCAN_TTL_MINUTES": "5"}).scan_ttl_minutes == 5


def test_status_tells_when_the_scan_expires(client):
    scan_id, _ = start(client)
    status = client.get(f"/api/scan/{scan_id}").json()
    created = datetime.fromisoformat(status["created_at"])
    assert datetime.fromisoformat(status["expires_at"]) - created == timedelta(minutes=30)
    assert "delete_token" not in status  # the token is only ever returned at creation


def test_a_scan_expires_after_the_ttl(tmp_path):
    """TTL 0.01 minutes = 0.6 s: readable at first, then 410 and every file gone."""
    settings = make_settings(tmp_path, ttl="0.01")
    client = TestClient(create_app(settings))
    scan_id, _ = start(client)
    assert client.get(f"/api/scan/{scan_id}/findings").status_code == 200
    export = settings.report_dir / scan_id / "report.json"
    assert export.is_file()
    time.sleep(0.8)
    assert client.get(f"/api/scan/{scan_id}").status_code == 410
    assert client.get(f"/api/scan/{scan_id}/findings").status_code == 410
    assert client.get(f"/api/scan/{scan_id}/report.html").status_code == 410
    assert not export.exists() and not (settings.report_dir / scan_id).exists()
    assert client.get("/api/scan/never-issued").status_code == 404  # unknown is not "gone"


def test_background_sweep_deletes_without_any_request(tmp_path):
    settings = make_settings(tmp_path, ttl="0.01")
    with TestClient(create_app(settings)) as client:  # the context manager runs the sweep loop
        scan_id, _ = start(client)
        assert (settings.report_dir / scan_id).is_dir()
        time.sleep(1.6)  # TTL 0.6 s, sweep every 0.2 s: no API call in between
        assert not (settings.report_dir / scan_id).exists()
        assert client.app.state.store.get(scan_id) is None


def test_sweep_removes_orphaned_temp_files_and_exports(tmp_path):
    settings = make_settings(tmp_path, ttl="0.01")
    client = TestClient(create_app(settings))
    store = client.app.state.store
    orphan_temp = settings.upload_dir / "scan-crashed"
    orphan_temp.mkdir(parents=True)
    (orphan_temp / "upload.zip").write_bytes(b"left behind")
    orphan_export = settings.report_dir / ("a" * 32)  # exports from before a restart
    orphan_export.mkdir(parents=True)
    (orphan_export / "report.json").write_text("{}")
    old = time.time() - 60
    for path in (orphan_temp, orphan_export):
        os.utime(path, (old, old))
    fresh = settings.upload_dir / "scan-fresh"  # younger than the TTL: a scan may be starting
    fresh.mkdir()
    os.utime(fresh, (time.time() + 60, time.time() + 60))
    assert store.sweep_orphans() == 2
    assert not orphan_temp.exists() and not orphan_export.exists()
    assert fresh.exists()


def test_delete_with_the_right_token_removes_everything(client, settings):
    scan_id, token = start(client)
    export_dir = settings.report_dir / scan_id
    assert export_dir.is_dir()
    leftover = settings.upload_dir / "scan-leftover"
    leftover.mkdir()
    client.app.state.store.update(scan_id, work_dir=leftover)  # a temp folder still owned by the scan
    response = client.delete(f"/api/scans/{scan_id}", headers={"X-Delete-Token": token})
    assert response.status_code == 204
    assert not export_dir.exists() and not leftover.exists()
    assert client.get(f"/api/scan/{scan_id}").status_code == 410
    assert client.get(f"/api/scan/{scan_id}/findings").status_code == 410
    assert client.delete(f"/api/scans/{scan_id}", headers={"X-Delete-Token": token}).status_code == 410


def test_delete_with_the_wrong_token_is_refused(client, settings):
    mine, my_token = start(client)
    theirs, their_token = start(client)
    for headers in ({"X-Delete-Token": "wrong"}, {"X-Delete-Token": their_token}, {}):
        assert client.delete(f"/api/scans/{mine}", headers=headers).status_code == 403, headers
    assert client.get(f"/api/scan/{mine}/findings").status_code == 200  # still there
    assert (settings.report_dir / mine).is_dir()
    # the same through the beacon endpoint
    assert client.post(f"/api/scans/{mine}/delete", json={"token": their_token}).status_code == 403
    assert client.post(f"/api/scans/{mine}/delete", content=b"not json").status_code == 403
    assert client.get(f"/api/scan/{mine}").status_code == 200
    assert client.delete("/api/scans/does-not-exist", headers={"X-Delete-Token": my_token}).status_code == 404


def test_beacon_delete_uses_post_with_a_json_token(client, settings):
    """navigator.sendBeacon can only POST, so pagehide uses POST /api/scans/{id}/delete."""
    scan_id, token = start(client)
    response = client.post(f"/api/scans/{scan_id}/delete", content=f'{{"token": "{token}"}}',
                           headers={"Content-Type": "text/plain"})
    assert response.status_code == 204
    assert client.get(f"/api/scan/{scan_id}").status_code == 410
    assert not (settings.report_dir / scan_id).exists()


def test_there_is_no_clear_all_endpoint(client):
    start(client)
    assert client.delete("/api/scans").status_code in (404, 405)
    assert client.delete("/api/scan").status_code in (404, 405)
    assert client.post("/api/scans/delete").status_code in (404, 405)
    paths = {route.path for route in client.app.routes}
    assert not any(p.rstrip("/").endswith(("/scans", "/clear", "/purge")) for p in paths)


def test_deleting_a_running_scan_leaves_nothing_behind(client, settings):
    store = client.app.state.store
    work = settings.upload_dir / "scan-running"
    work.mkdir(parents=True)
    job = store.create("x", "zip", work)
    store.update(job.id, status="running")
    assert store.delete(job.id, job.delete_token) == "deleted"
    assert not work.exists() and store.get(job.id) is None
    assert store.update(job.id, step="scanning") is False  # the scan thread notices it is gone


def test_saved_samples_are_loadable_and_outside_the_ttl(tmp_path):
    settings = make_settings(tmp_path, ttl="0.01")
    client = TestClient(create_app(settings))
    listing = client.get("/api/samples").json()
    names = {s["name"] for s in listing}
    assert {"target_app", "target_app_js", "juice-shop"} <= names
    assert all(s["id"] == f"sample-{s['name']}" and s["total"] > 0 for s in listing)
    time.sleep(0.8)  # far beyond the TTL
    report = client.get("/api/samples/target_app/findings")
    assert report.status_code == 200 and report.json()["target"] == "target_app"
    for fmt in ("json", "html", "sarif"):
        assert client.get(f"/api/samples/target_app/report.{fmt}").status_code == 200
    traversal = client.get("/api/samples/..%2F..%2Fsecret/findings")  # httpx normalises it away from /api
    assert "application/json" not in traversal.headers.get("content-type", "")
    for name in ("nope", "target_app..", "%2e%2e", "target_app%2Fx"):
        assert client.get(f"/api/samples/{name}/findings").status_code == 404, name
