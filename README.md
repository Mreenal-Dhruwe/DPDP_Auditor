# DPDP Compliance Auditor

Scans an application's source code and configuration for personal-data mishandling and
maps each finding to India's DPDP Act, 2023 and DPDP Rules, 2025.
Hackasol 5.0 · Track 3 Cybersecurity · CS-01.

> Legal mapping is indicative, not legal advice.

## Setup
```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Frontend (needs Node.js 22.22+, required by react-router 8):
```
cd frontend
npm install
npm run dev        # http://localhost:5173
npm run dev:mock   # same UI with a simulated API (no backend needed)
npm run e2e        # end-to-end test against the running backend + dev server (-- --git adds Juice Shop)
npm run build      # frontend/dist, then served by uvicorn on http://localhost:8000
```
Backend:
```
uvicorn backend.main:app --reload --port 8000
```

## Engine (work in progress)
```
python -m scanner.rules_loader                    # validate rules/dpdp_rules.yml, print a summary
python -m scanner.cli target_app --out report/    # scan a folder -> report/report.json
python -m scanner.evaluate                        # precision/recall on target_app vs ground_truth.yml
python -m scanner.evaluate target_app_js --ground-truth ground_truth_js.yml   # the JS/TS target
python -m scripts.make_mock_report                # regenerate frontend/src/mock/report.json
python -m scripts.make_ts_types                   # regenerate frontend/src/types/contract.ts
python -m pytest                                  # all tests
```
`target_app/` is the deliberately vulnerable demo app; `ground_truth.yml` is its answer key.

## Try the single-rule demo
```
cd demo
python scanner.py target_app    # one HIGH finding
python scanner.py fixed_app     # no findings
```

## Preview the rule catalogue
```
python rules/build_preview.py rules/dpdp_rules.yml rules/preview.html
```

The full project plan is in CLAUDE.md.
