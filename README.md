# DPDP Compliance Auditor

Scans an application's source code and configuration, finds where personal data is
mishandled, and maps every finding to **India's Digital Personal Data Protection Act, 2023**
and the **DPDP Rules, 2025**: the file and line, the Act section and Rule, a severity with its
reason, the penalty cap and a recommended fix.

Hackasol 5.0 · Track 3 Cybersecurity · Problem CS-01.

> Legal mapping is indicative, not legal advice.

| Deliverable | Where |
|---|---|
| 1. The scanner and its source code | `scanner/` (engine and CLI), `backend/` (API), `frontend/` (web app) |
| 2. The compliance report for our target application | [`samples/target_app/report.html`](samples/target_app/report.html) (also `.json` and `.sarif`) |
| 3. The list of checks and rules we wrote | [`rules/dpdp_rules.yml`](rules/dpdp_rules.yml): 28 rules, summarised [below](#rules) |

Also in `samples/`: reports for OWASP Juice Shop and our JavaScript target, with a manual
review of the Juice Shop findings ([`samples/README.md`](samples/README.md)).

---

## Quick start

### With Docker (one container: web app + API)
```
docker build -t dpdp-auditor .
docker run --rm -p 8000:8000 dpdp-auditor
```
Open http://localhost:8000. The image includes the libraries for PDF export. Settings are
environment variables (see [`.env.example`](.env.example)), e.g. `-e MAX_UPLOAD_MB=100`.

### On your machine
Needs Python 3.13, Git, and Node.js 22.22+ for the web app.
```
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env              # optional: defaults work

python -m scanner.cli target_app --out report/    # scan a folder from the command line
```
Web app (two terminals):
```
uvicorn backend.main:app --reload --port 8000
cd frontend && npm install && npm run dev        # http://localhost:5173
```
Or build the frontend once (`cd frontend && npm run build`) and uvicorn serves everything on
http://localhost:8000. `npm run dev:mock` runs the UI with a simulated API, no backend
needed. PDF export needs WeasyPrint's Pango libraries; without them (usual on Windows) the
API answers 501 and the HTML report is the printable version.

---

## Usage

### Command line (the demo backup: no server, no browser)
```
python -m scanner.cli <folder> --out report/                 # report.json, report.html, report.sarif
python -m scanner.cli <folder> --out report/ --formats json  # choose formats
```
It prints each finding with its location and masked evidence, then writes the reports.

### Web app
The landing page (`/`) introduces the tool; "Start a scan" opens the workspace. A charcoal
rail on the left links the screens of the current scan:

1. **New scan** (`/scan`) - drop a `.zip` of the project, or paste a public Git URL
   (GitHub, GitLab, Bitbucket; "Use OWASP Juice Shop" fills one in). The progress view
   follows each stage and, if the scan fails, says where and why.
2. **Overview** (`/scans/<id>`) - findings by severity split by detection confidence (each
   row filters), findings per DPDP provision (click a bar to filter), a scan summary, what
   the scan covered, which kinds of personal data are exposed, the review queue, and the
   findings table. Filters live in the URL, so a link shows the same view.
3. **Findings** (`/scans/<id>/findings`) - a review board (Open, Triaged, In progress,
   Resolved): drag cards between columns or use the status menu on each card (keyboard
   and touch). Review status is kept in your browser; the scanner's severity, confidence
   and legal mapping never change. A card opens the evidence drawer: masked code around
   the flagged line, the law card (section, Rule, requirement, penalty cap), severity
   and reason, confidence, the fix, and exports.
4. **Report** (`/scans/<id>/report`) - the summary, coverage, low-confidence findings to
   verify by hand, and downloads (HTML, PDF, SARIF, JSON).
5. **Rule catalogue** (`/rules`) - the 28 rules with their legal references.

"View sample" on the landing page opens the target_app report without any backend.

### API
| Endpoint | |
|---|---|
| `POST /api/scan` | multipart zip (field `file`) or JSON `{"git_url": ...}` -> `202 {"scan_id"}` |
| `GET /api/scan/{id}` | status: `queued` / `running` / `done` / `failed`, the current step, summary |
| `GET /api/scan/{id}/findings` | the report (JSON) |
| `GET /api/scan/{id}/report.{json,html,sarif,pdf}` | downloads |
| `GET /api/rules` | the rule catalogue and which rules are checked automatically |
| `GET /api/health` | |

Interactive docs: http://localhost:8000/docs.

### Checking the scanner itself
```
python -m pytest                                  # 396 tests
python -m scanner.evaluate                        # precision/recall on target_app vs ground_truth.yml
python -m scanner.evaluate target_app_js --ground-truth ground_truth_js.yml
cd frontend && npm run e2e                        # browser test against the running app (-- --git: Juice Shop)
```

---

## How it works

```
Interface:  CLI  |  React web app  ->  FastAPI backend (/api)
Engine:     Ingest -> PII finder -> Detectors -> Rule engine (+ rules/dpdp_rules.yml)
Output:     Report (JSON, the master format) -> HTML / PDF / SARIF
```

- **Ingest** unpacks a zip or shallow-clones a Git URL into a temporary folder that is always
  deleted after the scan, and lists the files. Code is **only read, never imported or run**.
- **PII finder** recognises personal data by field name: exact names, synonyms (`ph_no`,
  `mob`, `contact_no`), word splitting (`customerPhoneNumber`), careful fuzzy matching, and
  value patterns (Aadhaar with its Verhoeff check digit, PAN, UPI, IFSC, +91 mobile, email).
  Names like `password_hash` or `aadhaar_encrypted` count as protected.
- **Detectors** (one module per category) return only *where* and *what was seen*: rule id,
  file, line, masked evidence, the personal data involved and a confidence level. They use
  four kinds of clue:
  1. patterns (secrets, identifiers)
  2. code structure, with Python's `ast` and tree-sitter for JavaScript/TypeScript (a log call
     whose arguments hold an email; a route that returns a whole user record)
  3. absence (consent can be given but no route withdraws it; a table with personal data
     that nothing ever deletes)
  4. configuration (Dockerfile, docker-compose, `.env`, CORS, debug flags)
- **Rule engine** looks the rule id up in `rules/dpdp_rules.yml`, the single source of legal
  meaning, and adds the title, law, penalty, severity, reason and fix. Severity follows the
  penalty Schedule of the Act (s.33): security safeguards up to Rs 250 crore, breach
  notification and children Rs 200 crore, and so on. **No LLM decides a finding or a severity**:
  the same code always gives the same report.
- **Reports**: `report.json` (validated with Pydantic), a self-contained HTML report, PDF,
  and SARIF 2.1.0 for GitHub code scanning. Every report states what was checked, so "no
  findings" is never read as "compliant". All 28 rules have a detector; the 7 that code can
  only partly show (a notice in a modal, backups set up in a cloud console ...) report with low
  confidence and say "verify manually".

Supported code: Python (Flask, FastAPI, Django, SQLAlchemy, raw SQL), JavaScript and
TypeScript (Express, Sequelize; route handlers are followed across files), HTML templates,
SQL schemas, Dockerfiles and config files.

### Security of the auditor itself
- uploaded code is never executed; uploads and clones are deleted right after each scan
- safe unzip: no absolute paths or `..` (zip slip), no symlinks, caps on size and file count
  (zip bombs); Git URLs only over https from an allow-list of hosts, without credentials
- secrets and personal data are masked in evidence and code excerpts (`sk_live_ab********`)
- reports expire after `REPORT_TTL_DAYS`; scan ids are random; the container runs as a
  non-root user with read-only code

---

## Rules

28 rules in [`rules/dpdp_rules.yml`](rules/dpdp_rules.yml), each with its legal references,
penalty, severity, reason and fix. All 28 have an automated detector (**Auto**); NOT-001,
CON-005, CON-006, SEC-009, TP-002, BR-001 and RET-003 report with low confidence.

| Rule | What it finds | Law | Severity | Auto |
|---|---|---|---|---|
| DPDP-NOT-001 | Personal data collected without a notice of data and purpose | s.5(1), Rule 3(b) | medium | yes |
| DPDP-CON-001 | Consent can be given but not withdrawn | s.6(4), s.6(6), Rule 3(c)(i) | high | yes |
| DPDP-CON-002 | Pre-ticked or default-true consent | s.6(1) | high | yes |
| DPDP-CON-003 | No evidence of consent stored | s.6(10) | medium | yes |
| DPDP-CON-004 | Personal data used without checking consent | s.4(1), s.6(1) | high | yes |
| DPDP-CON-005 | Over-collection beyond the stated purpose | s.6(1) | medium | yes |
| DPDP-CON-006 | Consent request offered in one language only | s.6(3) | low | yes |
| DPDP-SEC-001 | Personal data written to logs | s.8(5), Rule 6(1)(a) | high | yes |
| DPDP-SEC-002 | Personal data stored in plaintext | s.8(5), Rule 6(1)(a) | high | yes |
| DPDP-SEC-003 | Weak password hashing | s.8(5), Rule 6(1)(a) | high | yes |
| DPDP-SEC-004 | Hardcoded secrets or credentials | s.8(5), Rule 6(1)(b) | critical | yes |
| DPDP-SEC-005 | Personal data exposed by an unauthenticated route | s.8(5), Rule 6(1)(b) | critical | yes |
| DPDP-SEC-006 | Excessive data in API responses | s.8(5), Rule 6(1)(a) | high | yes |
| DPDP-SEC-007 | No access logging on personal-data reads | s.8(5), Rule 6(1)(c) | medium | yes |
| DPDP-SEC-008 | Insecure infrastructure configuration | s.8(5), Rule 6(1)(b), Rule 6(1)(g) | high | yes |
| DPDP-SEC-009 | No backup configured for personal-data stores | s.8(5), Rule 6(1)(d) | low | yes |
| DPDP-SEC-010 | Log retention shorter than one year | s.8(5), Rule 6(1)(e), Rule 8(3) | medium | yes |
| DPDP-TP-001 | Personal data sent to a third-party SDK | s.8(1), s.8(2), Rule 6(1)(f) | medium | yes |
| DPDP-TP-002 | Personal data stored or sent outside India | s.16(1), Rule 15 | info | yes |
| DPDP-BR-001 | No breach notification mechanism | s.8(6), Rule 7(1), Rule 7(2) | medium | yes |
| DPDP-RET-001 | Personal data with no erase or anonymise path | s.8(7), s.12(3), Rule 8 | high | yes |
| DPDP-RET-002 | Immediate hard delete with no minimum retention | Rule 8(3) | medium | yes |
| DPDP-RET-003 | No pre-erasure notice to the user | s.8(8), Rule 8(2) | low | yes |
| DPDP-CH-001 | Child data collected without parental consent flow | s.9(1), Rule 10 | high | yes |
| DPDP-CH-002 | Tracking or targeted ads possible for children | s.9(3) | critical | yes |
| DPDP-RT-001 | No way to access or export one's data | s.11, Rule 14(1) | medium | yes |
| DPDP-RT-002 | No correction or erasure endpoint | s.12, Rule 14 | medium | yes |
| DPDP-RT-003 | No grievance mechanism or contact published | s.8(9), s.8(10), s.13, Rule 9, Rule 14(3) | low | yes |

Legal references were checked against the official texts: the Rules were notified on
13 Nov 2025 (G.S.R. 846(E)); most of them apply from 13 May 2027. Two points the scanner
reflects: Rule 8(3) requires keeping personal data and logs for at least a year, so an
*immediate* hard delete is itself reported (RET-002); cross-border transfer is allowed
unless restricted (s.16), so it is reported as info only. To browse the rules as a page:
`python rules/build_preview.py rules/dpdp_rules.yml rules/preview.html`.

---

## Results

| Target | Findings | Accuracy |
|---|---|---|
| `target_app/` - our deliberately vulnerable Flask lending app | 13 (critical 3, high 8, medium 2) | 13/13 planted issues found, 0 false positives |
| `target_app_js/` - our Express + Sequelize app | 27 (critical 3, high 8, medium 11, low 3, info 2) | 27/27 planted issues found, 0 false positives |
| OWASP Juice Shop (1,494 files, about 20 s) | 60 (critical 28, high 27, medium 3, info 2) | reviewed by hand, see below |

The answer keys (`ground_truth.yml`, `ground_truth_js.yml`) list every planted issue with
its file, line and rule, and also the *compliant* look-alikes that must not be reported
(for example, a Mixpanel call that only runs for adults). `python -m scanner.evaluate`
recomputes precision and recall, and the test suite fails if either drops.

Juice Shop has no answer key. Our review of its 60 findings
([`samples/README.md`](samples/README.md)):
- **real and serious:**
  - passwords hashed with unsalted MD5 (`models/user.ts:73`, plus the routes that hash login passwords the same way)
  - 14 seed users with plaintext passwords in `data/static/users.yml`
  - committed private keys (`lib/insecurity.ts`, Terraform files)
  - card numbers stored as plain integers (`models/card.ts:38`)
  - the change-password endpoint sending the whole user record, password hash included (`routes/changePassword.ts:56`)
  - access logs deleted after 2 days (`server.ts:368`) and CloudWatch logs after 30 days, against Rule 8(3)'s one year
- **info:** both Terraform setups deploy to `eu-west-1` (outside India; allowed unless restricted, s.16)
- **real pattern, not app code:** MD5 login code repeated in Juice Shop's coding-challenge answer files
- **low confidence by design:**
  - tokens and hashes in test files
  - "no erase path" for four models: Juice Shop generates REST endpoints with finale-rest, so a delete route may exist outside the code

---

## Limitations

- **Static analysis only.** It reads code; it cannot see contracts, privacy policies,
  databases, cloud consoles or how staff actually work. Seven rules can only be partly
  judged from code; their findings have low confidence and say "verify manually".
- **No ownership checks.** A route that requires login but lets a user read *someone else's*
  record (an IDOR, like Juice Shop's baskets) is not detected.
- **Data flow is shallow.** Values are followed within a function and through simple
  assignments, not through `.map()`, object spread or across many function calls.
- **Frameworks:** Flask, FastAPI, Django, SQLAlchemy, Express and Sequelize. Prisma,
  Mongoose, Spring, Go and PHP frameworks are not analysed yet. Endpoints generated at runtime
  (finale-rest, DRF routers) and handlers inside npm packages are invisible.
- **Heuristics can be wrong.** Each finding carries a confidence level; low-confidence
  findings say why (e.g. "may exist outside the scanned code").
- **Scans live in memory.** Restarting the server forgets finished scans (their files are
  deleted after `REPORT_TTL_DAYS`).
- **PDF export** needs WeasyPrint's system libraries; they are in the Docker image.

---

## Project layout
```
scanner/          engine: ingest, PII finder, detectors/, rules loader, reports, CLI, evaluator
backend/          FastAPI app and in-memory scan jobs
frontend/         React + Vite + TypeScript + Tailwind web app (types generated from the models)
rules/            dpdp_rules.yml - the 28 rules and their legal mapping
target_app/       deliberately vulnerable Flask app; answer key: ground_truth.yml
target_app_js/    deliberately vulnerable Express app; answer key: ground_truth_js.yml
samples/          saved reports for target_app, target_app_js and Juice Shop
tests/            pytest, with a vulnerable and a fixed fixture for every detector
demo/             the first single-rule prototype
Dockerfile        one image for the web app and the API
```
Contributor notes, design decisions and the build plan are in [`CLAUDE.md`](CLAUDE.md); the
demo script is in [`DEMO.md`](DEMO.md).
