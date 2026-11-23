"""FastAPI app (planned for hours 14-24). Run with: uvicorn backend.main:app --reload --port 8000

Endpoints (see CLAUDE.md):
    POST /api/scan                                   zip upload or {"git_url": ...} -> {"scan_id": ...}
    GET  /api/scan/{scan_id}                         status (queued/running/done/failed) + step
    GET  /api/scan/{scan_id}/findings                Report JSON (scanner.models.Report)
    GET  /api/scan/{scan_id}/report.{html|pdf|sarif|json}
    GET  /api/rules                                  rule catalogue (scanner.rules_loader)
    GET  /api/health
In production it also serves the built frontend from frontend/dist.
"""
