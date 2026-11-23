"""FastAPI backend. It only calls the scanner package; no detection logic lives here.

    uvicorn backend.main:app --reload --port 8000

Endpoints:
    POST /api/scan                              zip upload (form field "file") or JSON {"git_url": ...}
                                                -> 202 {"scan_id": ...}; the scan runs in the background
    GET  /api/scan/{scan_id}                    status (queued/running/done/failed), step, summary
    GET  /api/scan/{scan_id}/findings           the Report JSON (scanner.models.Report)
    GET  /api/scan/{scan_id}/report.{fmt}       download: json, html, sarif, pdf (501 without Pango)
    GET  /api/rules                             the rule catalogue (+ which rules have detectors)
    GET  /api/health
In production (frontend/dist exists) it also serves the built React app from "/".

Upload safety: size checked from Content-Length and again while saving (MAX_UPLOAD_MB),
.zip only, unpacked by scanner.ingest.safe_unzip in a temp folder that is deleted after
the scan. Git: https on ALLOWED_GIT_HOSTS only. Scan ids are random UUIDs.
"""

import tempfile
import zipfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile

from backend.jobs import Job, JobStore, run_scan, safe_target
from scanner import __version__
from scanner.config import PROJECT_ROOT, Settings, get_settings
from scanner.detectors import DETECTORS, covered_rules
from scanner.ingest import IngestError, remove_tree, repo_name, validate_git_url
from scanner.report.pdf_out import PdfUnavailable, render_pdf
from scanner.rules_loader import load_rules

MB = 1024 * 1024
DOWNLOADS = {
    "json": ("report.json", "application/json"),
    "html": ("report.html", "text/html; charset=utf-8"),
    "sarif": ("report.sarif", "application/sarif+json"),
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    catalogue = load_rules(settings.rules_file)
    store = JobStore()
    app = FastAPI(title="DPDP Compliance Auditor API", version=__version__)
    app.state.settings, app.state.store = settings, store
    # Development: the Vite dev server proxies /api, so CORS is only a fallback for direct calls.
    app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
                       allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    def finished_job(scan_id: str) -> Job:
        job = existing_job(scan_id)
        if job.status != "done":
            raise HTTPException(409, f"scan is {job.status}" + (f": {job.error}" if job.error else ""))
        return job

    def existing_job(scan_id: str) -> Job:
        store.purge_expired(settings.report_ttl_days)
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(404, "scan not found (unknown id, or its reports have expired)")
        return job

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "rules": len(catalogue.rules),
                "detectors": len(DETECTORS), "rules_checked": len(covered_rules())}

    @app.get("/api/rules")
    def rules() -> dict:
        return {
            "meta": catalogue.meta.model_dump(),
            "penalty_caps": {key: cap.model_dump() for key, cap in catalogue.penalty_caps.items()},
            "severity_model": catalogue.severity_model,
            "rules": [rule.model_dump() for rule in catalogue.rules],
            "checked": sorted(covered_rules()),
        }

    @app.post("/api/scan", status_code=202)
    async def start_scan(request: Request, background: BackgroundTasks) -> dict:
        settings.upload_dir.mkdir(parents=True, exist_ok=True)
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            try:
                body = await request.json()
                url = validate_git_url(str(body.get("git_url", "")), settings.allowed_git_hosts)
            except IngestError as exc:
                raise HTTPException(400, str(exc)) from None
            except (ValueError, AttributeError):
                raise HTTPException(400, 'send JSON like {"git_url": "https://github.com/owner/repo"}') from None
            job = store.create(repo_name(url), "git")
            work = Path(tempfile.mkdtemp(prefix="scan-", dir=settings.upload_dir))
            background.add_task(run_scan, store, job.id, work, settings, catalogue, git_url=url)
            return {"scan_id": job.id}

        if not content_type.startswith("multipart/form-data"):
            raise HTTPException(415, "upload a .zip as multipart form field 'file', or send JSON {\"git_url\": ...}")
        if int(request.headers.get("content-length") or 0) > settings.max_upload_mb * MB + MB:
            raise HTTPException(413, f"upload larger than {settings.max_upload_mb} MB")
        form = await request.form(max_files=1, max_fields=5)
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise HTTPException(400, "send the zip as multipart form field 'file'")
        if not (upload.filename or "").lower().endswith(".zip"):
            raise HTTPException(400, "only .zip uploads are accepted")
        work = Path(tempfile.mkdtemp(prefix="scan-", dir=settings.upload_dir))
        saved, size = work / "upload.zip", 0
        try:
            with saved.open("wb") as out:
                while chunk := await upload.read(MB):
                    size += len(chunk)
                    if size > settings.max_upload_mb * MB:
                        raise HTTPException(413, f"upload larger than {settings.max_upload_mb} MB")
                    out.write(chunk)
            if not zipfile.is_zipfile(saved):
                raise HTTPException(400, "the upload is not a valid zip file")
        except HTTPException:
            remove_tree(work)
            raise
        job = store.create(safe_target(upload.filename or "upload.zip"), "zip")
        background.add_task(run_scan, store, job.id, work, settings, catalogue)
        return {"scan_id": job.id}

    @app.get("/api/scan/{scan_id}")
    def scan_status(scan_id: str) -> dict:
        return existing_job(scan_id).public()

    @app.get("/api/scan/{scan_id}/findings")
    def findings(scan_id: str) -> Response:
        job = finished_job(scan_id)
        return Response(job.report.model_dump_json(), media_type="application/json")

    @app.get("/api/scan/{scan_id}/report.{fmt}")
    def download(scan_id: str, fmt: str) -> Response:
        job = finished_job(scan_id)
        filename = f"dpdp-report-{job.target}.{fmt}"
        if fmt == "pdf":
            try:
                pdf = render_pdf(job.report, catalogue)
            except PdfUnavailable as exc:
                raise HTTPException(501, str(exc)) from None
            return Response(pdf, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "format must be one of: json, html, sarif, pdf")
        name, media_type = DOWNLOADS[fmt]
        return FileResponse(job.report_dir / name, media_type=media_type, filename=filename)

    dist = PROJECT_ROOT / "frontend" / "dist"
    if dist.is_dir():  # production: one server for the UI and the API
        app.mount("/", StaticFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
