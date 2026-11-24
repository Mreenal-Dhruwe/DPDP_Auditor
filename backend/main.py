"""FastAPI backend. It only calls the scanner package; no detection logic lives here.

    uvicorn backend.main:app --reload --port 8000

Endpoints:
    POST /api/scan                              zip upload (form field "file") or JSON {"git_url": ...}
                                                -> 202 {"scan_id", "delete_token"}; runs in the background
    GET  /api/scan/{scan_id}                    status (queued/running/done/failed), step, summary, expires_at
    GET  /api/scan/{scan_id}/findings           the Report JSON (scanner.models.Report)
    GET  /api/scan/{scan_id}/report.{fmt}       download: json, html, sarif, pdf (501 without Pango)
    DELETE /api/scans/{scan_id}                 delete a scan now; header X-Delete-Token must match the token
                                                issued at creation (403 otherwise). 204 on success.
    POST /api/scans/{scan_id}/delete            the same for navigator.sendBeacon (which can only POST):
                                                JSON body {"token": "..."}
    GET  /api/samples                           saved sample reports (never expire; a demo fallback)
    GET  /api/samples/{name}/findings           and /report.{json,html,sarif,pdf}
    GET  /api/rules                             the rule catalogue (+ which rules have detectors)
    GET  /api/health

Scans are short-lived: SCAN_TTL_MINUTES (default 30) after creation the job, its exports and
leftover temp files are deleted by a background sweep; an expired or deleted scan answers 410,
an id never issued answers 404. There is no endpoint that deletes every scan.
In production (frontend/dist exists) it also serves the built React app from "/"; client-side
routes such as /scans/<id> get index.html, so reloading or sharing those links works.

Upload safety: size checked from Content-Length and again while saving (MAX_UPLOAD_MB),
.zip only, unpacked by scanner.ingest.safe_unzip in a temp folder that is deleted after
the scan. Git: https on ALLOWED_GIT_HOSTS only. Scan ids are random UUIDs.
"""

import asyncio
import contextlib
import json
import logging
import tempfile
import zipfile
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.jobs import Job, JobStore, run_scan, safe_target
from scanner import __version__
from scanner.config import PROJECT_ROOT, Settings, get_settings
from scanner.detectors import DETECTORS, covered_rules
from scanner.ingest import IngestError, remove_tree, repo_name, validate_git_url
from scanner.models import Report
from scanner.report.pdf_out import PdfUnavailable, render_pdf
from scanner.rules_loader import load_rules

MB = 1024 * 1024
jobs_log = logging.getLogger("dpdp.sweep")
DOWNLOADS = {
    "json": ("report.json", "application/json"),
    "html": ("report.html", "text/html; charset=utf-8"),
    "sarif": ("report.sarif", "application/sarif+json"),
}


class SpaFiles(StaticFiles):
    """The built React app. A path that is not a file and has no extension (a react-router
    route like /scans/<id>) gets index.html; unknown /api/... paths and missing assets stay 404."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            route = path.replace("\\", "/")  # Starlette gives an OS path: api\nope on Windows
            last = route.rsplit("/", 1)[-1]
            if exc.status_code != 404 or route == "api" or route.startswith("api/") or "." in last:
                raise
            return await super().get_response("index.html", scope)


GONE = "this scan has expired or was deleted"


def create_app(settings: Settings | None = None, frontend_dist: Path | None = None) -> FastAPI:
    settings = settings or get_settings()
    catalogue = load_rules(settings.rules_file)
    store = JobStore(settings.scan_ttl_minutes, settings.report_dir, settings.upload_dir)
    sweep_every = min(60.0, max(0.2, store.ttl.total_seconds() / 4))

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        async def sweeper() -> None:
            while True:
                await asyncio.sleep(sweep_every)
                try:
                    await asyncio.to_thread(lambda: (store.sweep(), store.sweep_orphans()))
                except Exception:  # a failed sweep must never stop the next one
                    jobs_log.exception("sweep failed")

        task = asyncio.create_task(sweeper())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="DPDP Compliance Auditor API", version=__version__, lifespan=lifespan)
    app.state.settings, app.state.store = settings, store
    # Development: the Vite dev server proxies /api, so CORS is only a fallback for direct calls.
    app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
                       allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-Delete-Token"])

    def finished_job(scan_id: str) -> Job:
        job = existing_job(scan_id)
        if job.status != "done":
            raise HTTPException(409, f"scan is {job.status}" + (f": {job.error}" if job.error else ""))
        return job

    def existing_job(scan_id: str) -> Job:
        store.sweep()  # an expired scan is deleted before it can be read
        job = store.get(scan_id)
        if job is None:
            raise HTTPException(410, GONE) if store.is_gone(scan_id) else HTTPException(404, "scan not found")
        return job

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "rules": len(catalogue.rules),
                "detectors": len(DETECTORS), "rules_checked": len(covered_rules()),
                "scan_ttl_minutes": settings.scan_ttl_minutes}

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
            work = Path(tempfile.mkdtemp(prefix="scan-", dir=settings.upload_dir))
            job = store.create(repo_name(url), "git", work)
            background.add_task(run_scan, store, job.id, work, settings, catalogue, git_url=url)
            return {"scan_id": job.id, "delete_token": job.delete_token}

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
        job = store.create(safe_target(upload.filename or "upload.zip"), "zip", work)
        background.add_task(run_scan, store, job.id, work, settings, catalogue)
        return {"scan_id": job.id, "delete_token": job.delete_token}

    @app.get("/api/scan/{scan_id}")
    def scan_status(scan_id: str) -> dict:
        return existing_job(scan_id).public(store.ttl)

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

    def delete_scan(scan_id: str, token: str | None) -> Response:
        result = store.delete(scan_id, token or "")
        if result == "deleted":
            return Response(status_code=204)
        if result == "forbidden":
            raise HTTPException(403, "wrong or missing delete token: only the visitor who started the scan can delete it")
        raise HTTPException(410, GONE) if result == "gone" else HTTPException(404, "scan not found")

    @app.delete("/api/scans/{scan_id}", status_code=204)
    def delete_scan_api(scan_id: str, x_delete_token: str | None = Header(None)) -> Response:
        return delete_scan(scan_id, x_delete_token)

    @app.post("/api/scans/{scan_id}/delete", status_code=204)
    async def delete_scan_beacon(scan_id: str, request: Request) -> Response:
        """The same delete for navigator.sendBeacon, which can only POST: {"token": "..."}."""
        try:
            token = json.loads((await request.body()) or b"{}").get("token")
        except (ValueError, AttributeError):
            token = None
        return delete_scan(scan_id, token if isinstance(token, str) else None)

    # --- saved samples: reports generated earlier by the CLI; read-only, never expire ---------------
    def sample_folders() -> dict[str, Path]:
        base = settings.samples_dir
        if not base.is_dir():
            return {}
        return {d.name: d for d in sorted(base.iterdir()) if (d / "report.json").is_file()}

    def sample_folder(name: str) -> Path:
        folder = sample_folders().get(name)  # looked up in the listing: no path traversal
        if folder is None:
            raise HTTPException(404, "no such saved sample")
        return folder

    @app.get("/api/samples")
    def list_samples() -> list[dict]:
        found = []
        for name, folder in sample_folders().items():
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            found.append({"id": f"sample-{name}", "name": name, "target": report["target"],
                          "total": report["summary"]["total"], "by_severity": report["summary"]["by_severity"],
                          "generated_at": report["generated_at"]})
        return found

    @app.get("/api/samples/{name}/findings")
    def sample_findings(name: str) -> Response:
        return Response((sample_folder(name) / "report.json").read_bytes(), media_type="application/json")

    @app.get("/api/samples/{name}/report.{fmt}")
    def sample_download(name: str, fmt: str) -> Response:
        folder = sample_folder(name)
        filename = f"dpdp-sample-{name}.{fmt}"
        if fmt == "pdf":
            try:
                pdf = render_pdf(Report.model_validate_json((folder / "report.json").read_bytes()), catalogue)
            except PdfUnavailable as exc:
                raise HTTPException(501, str(exc)) from None
            return Response(pdf, media_type="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{filename}"'})
        if fmt not in DOWNLOADS:
            raise HTTPException(404, "format must be one of: json, html, sarif, pdf")
        file_name, media_type = DOWNLOADS[fmt]
        return FileResponse(folder / file_name, media_type=media_type, filename=filename)

    dist = frontend_dist or PROJECT_ROOT / "frontend" / "dist"
    if dist.is_dir():  # production: one server for the UI and the API
        app.mount("/", SpaFiles(directory=dist, html=True), name="frontend")
    return app


app = create_app()
