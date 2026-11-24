"""In-memory scan jobs, run with FastAPI BackgroundTasks.

Each job works in its own temp folder under UPLOAD_DIR (the uploaded zip, or the git
clone). The folder is deleted in try/finally as soon as the scan ends, success or not:
uploaded code is never kept. The reports (json, html, sarif) go to REPORT_DIR/<scan_id>/.

Scans are short-lived. A scan (its job, its exports and any temp files) is deleted
SCAN_TTL_MINUTES after it was created (default 30) by `JobStore.sweep`, which runs on every
API request and from a background loop in backend/main.py, or at once when its owner asks:
every scan gets a random delete token at creation, and only that token can delete it. A
deleted or expired scan answers 410 (its id stays in a small tombstone list); an id the
server never issued answers 404.

Jobs live in memory, so restarting the server forgets them. That is fine for the demo;
a database is the next step if scans must survive restarts.
"""

import hmac
import logging
import re
import secrets
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from scanner.config import Settings
from scanner.engine import scan_folder
from scanner.ingest import IngestError, clone_git, remove_tree, safe_unzip
from pydantic import BaseModel, ConfigDict

from scanner.models import Report, Summary
from scanner.report.html_out import write_html
from scanner.report.json_out import write_json
from scanner.report.sarif_out import write_sarif
from scanner.rules_loader import RuleCatalogue, RulesError

log = logging.getLogger("dpdp.jobs")
Status = Literal["queued", "running", "done", "failed"]
Source = Literal["zip", "git"]
STEPS = {
    "zip": ["queued", "unpacking", "scanning", "writing reports", "done"],
    "git": ["queued", "cloning", "scanning", "writing reports", "done"],
}


def safe_target(name: str) -> str:
    """A display name from an upload's filename: 'My App (v2).zip' -> 'My_App_v2'."""
    stem = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    stem = stem[:-4] if stem.lower().endswith(".zip") else stem
    cleaned = re.sub(r"[^\w.-]+", "_", stem).strip("._")[:80]
    return cleaned or "upload"


def now() -> datetime:
    return datetime.now(timezone.utc)


class ScanStarted(BaseModel):
    """Response of POST /api/scan. `delete_token` is shown once: whoever holds it can delete
    the scan early (DELETE /api/scans/{id}); it is never part of any other response."""

    model_config = ConfigDict(extra="forbid")
    scan_id: str
    delete_token: str


class ScanStatus(BaseModel):
    """Response of GET /api/scan/{id}: never paths, never raw evidence. `steps` lists every
    step of this kind of scan in order; `step` is the current one, or the one that failed."""

    model_config = ConfigDict(extra="forbid", json_schema_serialization_defaults_required=True)
    scan_id: str
    target: str
    source: Source
    status: Status
    step: str
    steps: list[str]
    created_at: datetime
    expires_at: datetime  # created_at + SCAN_TTL_MINUTES: the server deletes the scan then
    finished_at: datetime | None = None
    error: str | None = None
    summary: Summary | None = None  # set when the scan is done


@dataclass
class Job:
    id: str
    target: str
    source: Source
    status: Status = "queued"
    step: str = "queued"
    created_at: datetime = field(default_factory=now)
    finished_at: datetime | None = None
    error: str | None = None
    report: Report | None = None
    report_dir: Path | None = None
    work_dir: Path | None = None  # unpacked upload / clone, deleted when the scan ends
    delete_token: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)

    def public(self, ttl: timedelta) -> dict[str, Any]:
        """What GET /api/scan/{id} returns (a ScanStatus)."""
        return ScanStatus(
            scan_id=self.id, target=self.target, source=self.source, status=self.status, step=self.step,
            steps=STEPS[self.source], created_at=self.created_at, expires_at=self.created_at + ttl,
            finished_at=self.finished_at, error=self.error, summary=self.report.summary if self.report else None,
        ).model_dump(mode="json")


TOMBSTONES = 10_000  # remembered ids of deleted / expired scans (answer 410 instead of 404)


class JobStore:
    def __init__(self, ttl_minutes: float = 30, report_dir: Path | None = None, upload_dir: Path | None = None) -> None:
        self.ttl = timedelta(minutes=ttl_minutes)
        self.report_dir, self.upload_dir = report_dir, upload_dir
        self._jobs: dict[str, Job] = {}
        self._gone: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()  # background tasks run in a thread pool

    def create(self, target: str, source: str, work_dir: Path | None = None) -> Job:
        job = Job(id=uuid.uuid4().hex, target=target, source=source, work_dir=work_dir)  # random: ids can't be guessed
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def is_gone(self, job_id: str) -> bool:
        """True for a scan that existed and was deleted or expired (answer 410, not 404)."""
        with self._lock:
            return job_id in self._gone

    def update(self, job_id: str, **changes: Any) -> bool:
        """Change a job; False if it no longer exists (deleted while it was running)."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            for key, value in changes.items():
                setattr(job, key, value)
            return True

    def _discard(self, jobs: list[Job]) -> None:
        """Forget jobs and delete everything they left on disk: exports and temp files."""
        with self._lock:
            for job in jobs:
                self._jobs.pop(job.id, None)
                self._gone[job.id] = None
            while len(self._gone) > TOMBSTONES:
                self._gone.popitem(last=False)
        for job in jobs:
            for folder in (job.report_dir, self.report_dir / job.id if self.report_dir else None, job.work_dir):
                if folder is not None:
                    remove_tree(folder)

    def sweep(self) -> int:
        """Delete finished scans older than the TTL (a running scan is left to finish). Cheap:
        no disk access unless something expired, so it runs on every API request."""
        cutoff = now() - self.ttl
        with self._lock:
            expired = [j for j in self._jobs.values() if j.status in ("done", "failed") and j.created_at < cutoff]
        self._discard(expired)
        return len(expired)

    def sweep_orphans(self) -> int:
        """Delete leftovers no live scan owns, older than the TTL: temp folders of a crashed scan
        and exports from before a restart. Runs from the background loop."""
        cutoff = (now() - self.ttl).timestamp()
        with self._lock:
            live_work = {str(j.work_dir) for j in self._jobs.values() if j.work_dir}
            live_ids = set(self._jobs)
        removed = 0
        candidates = []
        if self.upload_dir and self.upload_dir.is_dir():
            candidates += [p for p in self.upload_dir.glob("scan-*") if str(p) not in live_work]
        if self.report_dir and self.report_dir.is_dir():
            candidates += [p for p in self.report_dir.iterdir() if p.is_dir() and p.name not in live_ids]
        for path in candidates:
            try:
                if path.stat().st_mtime < cutoff:
                    remove_tree(path)
                    removed += 1
            except OSError:
                continue
        return removed

    def delete(self, job_id: str, token: str) -> str:
        """'deleted', 'forbidden' (wrong token: nothing is deleted), 'gone' or 'missing'."""
        job = self.get(job_id)
        if job is None:
            return "gone" if self.is_gone(job_id) else "missing"
        if not hmac.compare_digest(job.delete_token.encode(), (token or "").encode()):
            return "forbidden"
        self._discard([job])
        return "deleted"


def run_scan(store: JobStore, job_id: str, work_dir: Path, settings: Settings, catalogue: RuleCatalogue,
             git_url: str | None = None) -> None:
    """Background task: unpack or clone, scan, write the reports. work_dir is always deleted."""
    job = store.get(job_id)
    if job is None:  # deleted before it started
        remove_tree(work_dir)
        return
    max_bytes = settings.max_upload_mb * 1024 * 1024
    source_dir = work_dir / "src"
    try:
        if git_url:
            store.update(job_id, status="running", step="cloning")
            clone_git(git_url, source_dir, settings.git_clone_timeout, max_bytes)
        else:
            store.update(job_id, status="running", step="unpacking")
            safe_unzip(work_dir / "upload.zip", source_dir, max_bytes, settings.max_files)
        store.update(job_id, step="scanning")
        report = scan_folder(source_dir, catalogue, max_files=settings.max_files, target=job.target)
        store.update(job_id, step="writing reports")
        out = settings.report_dir / job_id
        write_json(report, out)
        write_html(report, out, catalogue)
        write_sarif(report, out, catalogue)
        store.update(job_id, status="done", step="done", report=report, report_dir=out, finished_at=now())
    except (IngestError, RulesError) as exc:
        store.update(job_id, status="failed", error=str(exc), finished_at=now())
    except Exception:  # never show internals (paths, stack traces) to the client
        log.exception("scan %s failed", job_id)
        store.update(job_id, status="failed", error="internal error while scanning", finished_at=now())
    finally:
        remove_tree(work_dir)
        if store.get(job_id) is None:  # the owner deleted the scan while it was running
            remove_tree(settings.report_dir / job_id)
