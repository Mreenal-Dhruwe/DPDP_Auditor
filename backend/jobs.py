"""In-memory scan jobs, run with FastAPI BackgroundTasks.

Each job works in its own temp folder under UPLOAD_DIR (the uploaded zip, or the git
clone). The folder is deleted in try/finally as soon as the scan ends, success or not:
uploaded code is never kept. The reports (json, html, sarif) go to REPORT_DIR/<scan_id>/
and expire after REPORT_TTL_DAYS (purge_expired runs on every API request).

Jobs live in memory, so restarting the server forgets them. That is fine for the demo;
a database is the next step if scans must survive restarts.
"""

import logging
import re
import threading
import uuid
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
    """Response of POST /api/scan."""

    model_config = ConfigDict(extra="forbid")
    scan_id: str


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

    def public(self) -> dict[str, Any]:
        """What GET /api/scan/{id} returns (a ScanStatus)."""
        return ScanStatus(
            scan_id=self.id, target=self.target, source=self.source, status=self.status, step=self.step,
            steps=STEPS[self.source], created_at=self.created_at, finished_at=self.finished_at,
            error=self.error, summary=self.report.summary if self.report else None,
        ).model_dump(mode="json")


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()  # background tasks run in a thread pool

    def create(self, target: str, source: str) -> Job:
        job = Job(id=uuid.uuid4().hex, target=target, source=source)  # random: ids can't be guessed
        with self._lock:
            self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **changes: Any) -> None:
        with self._lock:
            job = self._jobs[job_id]
            for key, value in changes.items():
                setattr(job, key, value)

    def purge_expired(self, ttl_days: int) -> int:
        """Forget jobs older than ttl_days and delete their reports. Returns how many."""
        cutoff = now() - timedelta(days=ttl_days)
        with self._lock:
            expired = [job for job in self._jobs.values() if job.created_at < cutoff]
            for job in expired:
                del self._jobs[job.id]
        for job in expired:
            if job.report_dir is not None:
                remove_tree(job.report_dir)
        return len(expired)


def run_scan(store: JobStore, job_id: str, work_dir: Path, settings: Settings, catalogue: RuleCatalogue,
             git_url: str | None = None) -> None:
    """Background task: unpack or clone, scan, write the reports. work_dir is always deleted."""
    job = store.get(job_id)
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
