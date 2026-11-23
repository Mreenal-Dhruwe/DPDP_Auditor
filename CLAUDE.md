# DPDP Compliance Auditor — Project Brief

Hackasol 5.0 · Track 3 Cybersecurity · Problem CS-01 · 36-hour build.

## Goal
Build a tool that scans an application's source code and configuration, finds where
personal data is mishandled, and maps each finding to India's DPDP Act, 2023 and DPDP
Rules, 2025. Each finding needs: evidence (file + line), DPDP provision, severity
(critical/high/medium/low/info) with a short justification, and a recommended fix.

Required deliverables (from the problem statement):
1. The scanner and its source code.
2. The compliance report generated for our target application.
3. The list of checks and rules our team wrote (`rules/dpdp_rules.yml`).

Bonus features (only after the core works): consent-flow assessment, auto-generated
patches (unified diffs), live testing of running API endpoints.

## Key design decisions (already agreed — do not change without asking)
- Python 3.13 (local venv and the Docker image `python:3.13-slim`). Deterministic, rule-based engine. Findings and severity are NEVER decided
  by an LLM. An LLM may only be used optionally to word explanations or draft fixes.
- The scanner only READS uploaded code. It never imports, runs or executes it.
- `rules/dpdp_rules.yml` is the single source of truth for legal meaning: each rule has
  id, category, title, detects, targets, law (act, rules, requirement), penalty,
  severity, severity_reason, fix. Detectors in code reference rules only by id.
- Detection uses four kinds of clue:
  1. Pattern matching (regex for Aadhaar w/ Verhoeff, PAN, UPI, IFSC, +91 mobile, email;
     secrets).
  2. Structure via Python `ast` (e.g. a logger/print call whose args contain PII fields).
  3. Absence checks (e.g. consent-grant route exists but no withdraw route; PII table
     with no delete/anonymise path).
  4. Config/IaC checks (.env, Dockerfile, docker-compose, cloud YAML).
- PII field detection: exact names + synonym list (ph_no, mob, contact_no …) +
  normalisation (split camelCase/snake_case) + fuzzy match (difflib, cutoff ~0.8; max 1
  edit for words of 5 letters or fewer; skip common English words like none/done/one) +
  value regexes + validators/input types (e.g. type="tel"). Each finding carries a
  confidence level (high/medium/low) alongside severity.
- Severity is anchored to the Act's penalty Schedule (s.33): s.8(5) security Rs 250 cr;
  s.8(6) breach Rs 200 cr; s.9 children Rs 200 cr; s.10 SDF Rs 150 cr; any other
  provision Rs 50 cr.
- Interface: command line first (`python -m scanner.cli <path> --out report/`), then a
  React web app talking to a FastAPI backend. The CLI must always work on its own as the
  demo backup (together with the HTML report).
- Frontend: React + Vite + TypeScript + Tailwind CSS, in `frontend/`. Three screens:
  1. Upload & scan: drag-and-drop zip, Git URL field, Start Scan, progress steps.
  2. Results dashboard: stat tiles (critical/high/medium/low/info), chart by DPDP
     provision (Recharts), filterable findings table (severity, rule, file:line,
     provision, confidence).
  3. Finding detail: code viewer with the flagged line highlighted, law card (Act
     section + Rule + requirement), severity + reason, fix as a diff, export buttons
     (HTML, PDF, SARIF, JSON).
  Routing with react-router; plain fetch or a tiny api.ts wrapper; no heavy state library.
- Backend: FastAPI in `backend/`. Endpoints:
  - `POST /api/scan` — multipart zip upload or JSON {git_url}; returns {scan_id}.
    Runs the engine as a background task.
  - `GET /api/scan/{scan_id}` — status (queued/running/done/failed) + progress step.
  - `GET /api/scan/{scan_id}/findings` — the Report JSON.
  - `GET /api/scan/{scan_id}/report.{html|pdf|sarif|json}` — downloads.
  - `GET /api/rules` — the rule catalogue (for a rules page / tooltips).
  - `GET /api/health`.
  The backend only calls the engine (`scanner` package); no detection logic lives in it.
  In development, Vite proxies `/api` to `http://localhost:8000` (no CORS needed). In
  production FastAPI serves the built frontend from `frontend/dist`.
- Report outputs: JSON (Pydantic-validated, the master format), HTML (Jinja2),
  PDF (WeasyPrint), SARIF.

## Architecture
```
Interface:  CLI  |  React frontend  ->  FastAPI backend (/api)
Engine:     Ingest -> PII finder -> Detectors -> Rule engine (+ dpdp_rules.yml) -> severity
Output:     Report generator -> JSON / HTML / PDF / SARIF
```
- Ingest: unzip upload or clone git URL into a temp folder; list files; classify as
  code / schema / config / frontend.
- PII finder: inventory of where personal data appears, with confidence.
- Detectors: one module per category; each returns only rule_id + file + line + evidence.
- Rule engine: looks up rule_id in the YAML, adds law, penalty, severity, reason, fix.

### Finding contract (shared by every part — frozen in hours 0–4)
Source of truth: `scanner/models.py`. Detectors return a `Hit` (rule_id, file, line, evidence,
pii, confidence); `RuleCatalogue.to_finding()` in `scanner/rules_loader.py` adds the rest
from the YAML.
```json
{
  "id": "89229a868407",
  "rule_id": "DPDP-SEC-001",
  "title": "Personal data written to logs",
  "category": "Security",
  "scope": "line", "file": "app.py", "line": 7,
  "evidence": "print('New user:', em***@***, ******3210)",
  "context": {"start_line": 4, "lines": ["...", "...", "...", "    print('New user:', ...)", "...", "...", "..."]},
  "pii": ["email", "phone"], "confidence": "high",
  "law": {"act": ["s.8(5)"], "rules": ["Rule 6(1)(a)"], "requirement": "Secure personal data through ..."},
  "penalty": {"schedule_item": 1, "provision": "s.8(5) security safeguards", "cap": "Rs 250 crore"},
  "severity": "high", "severity_reason": "...",
  "fix": "Mask PII before logging"
}
```
- `scope` (same values as `scope` in ground_truth.yml) decides which location fields are set:
  `line` = one place (file and line required); `file` = a whole file, e.g. no USER in a
  Dockerfile (file required, `line` null); `project` = something missing everywhere (file/line
  optional and only point at related code, e.g. the consent-grant route; both null if none).
  The UI shows `Finding.location`-style text: "app.py:7", "Dockerfile", "project-wide (see app.py:125)".
- `id`: first 12 hex chars of sha256("rule_id|file|line", nulls as ""); stable across runs.
- `file`: forward slashes, relative to the scanned folder; absolute paths and `..` are rejected.
- `evidence`: one line, masked, at most 300 characters. Detectors mask secrets they find
  (`masking.mask_secret`); `to_finding()` always runs `masking.mask_evidence` as a safety net.
- `context`: source lines for the code viewer (uploads are deleted after a scan): 3 lines
  either side of `line`, indentation kept, each masked by the same safety net and then cut
  to 200 characters (mask first, so a cut never leaves half a secret). Null for `file` scope,
  for `project` scope without a related line, and when the file can't be read.
- Report (`report.json`): tool, tool_version, rules_version, target, generated_at, files_scanned,
  coverage {files_by_kind, rules_checked, rules_not_checked} (what "no findings" means),
  disclaimer, summary {total, by_severity (always all five keys), by_category, by_provision},
  findings (sorted critical → info, then file and line; repeats of the same id dropped).

## Verified legal facts (checked against official PDFs — keep these exact)
- Rules notified 13 Nov 2025 (G.S.R. 846(E)). Rules 3, 5–16, 22, 23 apply from 13 May 2027;
  Rule 4 (Consent Manager) from 13 Nov 2026.
- Rule 7: users told "without delay"; detailed report to the Board within 72 hours.
- Rule 8(3): ALL fiduciaries must keep personal data, traffic data and processing logs
  for at least one year, then erase. An immediate hard delete can itself be a gap.
- Rule 8(1)/(2) (3-year inactivity erasure + 48h notice) applies only to Third Schedule
  classes (large e-commerce, gaming, social media).
- Rule 15 / s.16: cross-border transfer is allowed unless restricted — report as INFO.
- Always include the disclaimer: "Legal mapping is indicative, not legal advice."

## Layout
```
scanner/
  __init__.py
  cli.py            # entry point: python -m scanner.cli <path> --out report/
  config.py         # reads settings from environment variables (see .env.example)
  ingest.py         # temp folder, safe unzip, git clone, file classification
  pii.py            # identifiers, field-name matching, fuzzy, confidence
  rules_loader.py   # load + validate rules/dpdp_rules.yml; to_finding() = rule engine
  engine.py         # scan_folder(): the pipeline, shared by CLI, backend and evaluator
  evaluate.py       # python -m scanner.evaluate: precision/recall vs ground_truth.yml
  detectors/        # consent, logs, storage, access, retention, thirdparty, children,
                    # rights, config_files, hardcoded_secrets; shared helpers routes.py,
                    # source.py, schemas.py, pii_refs.py, javascript.py (tree-sitter).
                    # Rule ownership + status in __init__.py. Done (12): CON-001, CON-002,
                    # SEC-001..005, SEC-008, TP-001, RET-001, RET-002, CH-001.
                    # JS/TS (Express + Sequelize): SEC-001, SEC-005, CON-001 (routes),
                    # SEC-002 + RET-001 (Sequelize models), SEC-003 (createHash/md5 incl.
                    # hash helpers called with passwords), SEC-004 (text). Express handlers
                    # are resolved across files (ES import, require, ns.fn(), factories,
                    # wrappers like asyncHandler(fn())): 100/163 Juice Shop routes.
                    # Known limits: no ownership (IDOR-behind-login) check; data reshaped
                    # via .map()/spread (...user.dataValues) is not traced; handlers from
                    # packages and generated endpoints (finale-rest) are invisible;
                    # Prisma/Mongoose not yet.
                    # Parsed files, routes and tables are cached on Project per scan.
  models.py         # Pydantic Finding, Report
  severity.py
  masking.py        # mask secrets and PII in evidence
  report/           # json_out.py, html_out.py (Jinja2, self-contained), pdf_out.py
                    # (WeasyPrint), sarif_out.py (validated against SARIF 2.1.0 schema)
scripts/make_mock_report.py  # writes frontend/src/mock/report.json from the real models
rules/dpdp_rules.yml
rules/build_preview.py
target_app/         # deliberately vulnerable Flask app with ~30 planted issues
ground_truth.yml    # answer key: planted issues (rule_id, file, line, anchor, scope),
                    # compliant decoys, not-applicable rules; format in its header
target_app_js/      # small Express + Sequelize app (JS/TS) for the JavaScript support
ground_truth_js.yml # its answer key; out_of_scope lists rules it does not judge
                    # (their findings are set aside by the evaluator, not counted as FPs)
tests/              # pytest: each rule has a vulnerable and a fixed fixture
backend/
  main.py           # FastAPI app (create_app(settings)), /api routes, serves frontend/dist
                    # in production. Done: all endpoints; PDF -> 501 when WeasyPrint's Pango
                    # libraries are missing (Windows); Docker needs apt libpango-1.0-0
                    # libpangoft2-1.0-0 for PDF
  jobs.py           # in-memory scan jobs + BackgroundTasks; per-job temp folder always
                    # deleted (ingest.remove_tree also clears read-only git files); reports in
                    # REPORT_DIR/<scan_id>/ expire after REPORT_TTL_DAYS. Git ingest: https on
                    # ALLOWED_GIT_HOSTS only, shallow clone via the git CLI (no GitPython)
frontend/           # React + Vite + TypeScript + Tailwind
  src/pages/        # Upload.tsx, Dashboard.tsx, FindingDetail.tsx
  src/components/   # SeverityBadge, LawCard, CodeViewer, FindingsTable, StatTiles
  src/api.ts        # typed calls to /api; types mirror the Finding contract
  vite.config.ts    # proxy /api -> http://localhost:8000
requirements.txt
.env.example
Dockerfile          # added in Phase 2
```

## Build phases: local first, then online
### Phase 1 — Build and test on the local machine (most of the 36 hours)
- Everything runs on the developer's laptop:
  - engine: `python -m scanner.cli target_app`, `pytest`
  - backend: `uvicorn backend.main:app --reload --port 8000`
  - frontend: `cd frontend && npm install && npm run dev` (opens http://localhost:5173)
- Test on target_app (precision/recall vs ground_truth.yml) and OWASP Juice Shop.

### Phase 2 — Package in Docker, still local (around hours 24–30)
- Write a multi-stage Dockerfile:
  1. `node:20-slim` stage builds the frontend (`npm ci && npm run build` -> frontend/dist).
  2. `python:3.13-slim` stage installs requirements, copies the code and frontend/dist,
     runs as a non-root user, exposes 8000, starts
     `uvicorn backend.main:app --host 0.0.0.0 --port 8000`.
- Verify: `docker build -t dpdp-auditor .` then `docker run -p 8000:8000 dpdp-auditor`
  and open http://localhost:8000 (one container serves both UI and API).

### Phase 3 — Put it online (end of hackathon or after)
- Push to GitHub, deploy the Dockerfile on Render or Hugging Face Spaces, set env vars in
  the host dashboard, prefer an India (Mumbai) region where available.
- Keep the local version ready as a demo backup.

### Team split
- Engine (1–2 people): scanner/ + rules + tests.
- Backend (shared with engine person): backend/.
- Frontend (React person): frontend/, starts on mock data at hour 4.
- Target & QA: target_app/, ground_truth.yml, Juice Shop run, metrics.

### Habits from day one (so Phase 2/3 need no rewrite)
1. Every new package goes into requirements.txt (Python) or package.json (frontend) immediately.
2. No hardcoded absolute paths; use pathlib and settings.
3. All settings come from environment variables via scanner/config.py, with defaults.
   Never commit a real .env.
4. Uploads go to a temp folder that is deleted after the scan, inside try/finally.
5. Evidence in reports is masked (secrets and PII) from the start.
6. Commit to GitHub often.
7. Never name a module or package after a standard-library module (use logs.py, not
   logging.py; hardcoded_secrets.py, not secrets.py). tests/test_naming.py enforces it.

## Security of the auditor itself
Build now (cheap, visible):
- Never execute uploaded code.
- Safe unzip: reject absolute paths and `..` (zip slip), skip symlinks, cap total
  uncompressed size (MAX_UPLOAD_MB) and file count (MAX_FILES) to stop zip bombs.
- Delete uploads right after the scan; expire stored reports after REPORT_TTL_DAYS.
- Mask secrets (e.g. `sk_live_ab********`) and PII (Aadhaar, phone, email) in evidence.
- Docker container runs as non-root.
Plan / pitch slide (build only if time allows):
- Each scan in a throwaway container: no network, CPU/memory/time limits, read-only FS.
- Backend: validate upload type/size before saving; restrict CORS to our own origin;
  never return raw evidence, only masked.
- HTTPS, login, per-user ownership check on every report (no IDOR), rate limits.
- Secrets in env vars / secret manager; encrypted storage; private database.
- Audit logs without code or PII; alerts on unusual downloads; breach plan per Rule 7.
- Dependency scanning (pip-audit / Dependabot).
- Offer a local/CI mode so companies never upload code.

## 36-hour plan
- 0–4h: freeze Finding contract + rule schema, repo skeleton, config.py, start target
  app + ground truth.
- 4–14h: ingest (safe unzip), PII inventory, config scanner, first 15 rules with tests.
- 14–24h: data-flow tracing (source -> sink), severity, remaining rules, report
  generator, FastAPI endpoints.
- Frontend runs in parallel from hour 4: build all three screens against a mock
  report JSON (`frontend/src/mock/report.json`, matching the Finding contract), then
  switch to the real API once the backend is up (target: hour 20).
- 24–31h: Dockerfile (Phase 2), consent-enforcement check, patches, live API probe
  (stretch), dashboard polish.
- 31–36h: precision/recall vs ground truth, Juice Shop run, README, demo script,
  optional deploy (Phase 3).
- Feature freeze at hour 30.

## Working style
- Build in small steps; after each step run the scanner on target_app and the tests.
- Prefer simple, readable code; the team are students, explain non-obvious choices briefly.
- Every detector must have a vulnerable + fixed test case.
- When the team makes a new decision, update this file.

## Existing starting material in this folder
- `rules/dpdp_rules.yml` — 28 rules, legal refs verified.
- `rules/build_preview.py` — validates the YAML and builds an HTML preview.
- `demo/` — working single-rule prototype (consent withdrawal, DPDP-CON-001) showing the
  rule-YAML + AST detector pattern. Use it as the reference for the detector style.
- `requirements.txt`, `.env.example`, `.gitignore` — starting setup.
