# Production integration handoff

The prototype shows one way to express the design. Use the real app's layout, component conventions, and responsive needs to guide the port. See [the package README](../README.md) for the design choices delegated to Claude.

## Run the prototype

From the project root, run `cd frontend`, `npm ci` and `npm run dev`. Run `npm run build` for TypeScript checking and the production bundle. Vite serves the prototype locally. React Router uses browser history, so configure the production host to serve the entry document for frontend routes.

## Transfer in stages

1. Compare the team's actual Pydantic Finding and Report models and generated report with [the sample JSON](../frontend/src/mock/report.json) and [typed presentation helpers](../frontend/src/data.ts). The project plan supplies the finding contract. Report-level coverage and metadata in this sample are prototype choices.
2. Keep the existing API client, auth, scan isolation, masking, error handling and upload controls in place. Transfer the [tokens](../frontend/src/styles.css), [responsive styles](../frontend/src/workspace.css), [brand asset](../frontend/public/mark.svg) and [shared UI](../frontend/src/ui.tsx) into the existing frontend in small changes. Reconcile global Tailwind resets with the host application.
3. Feed real report data through a typed adapter. Expose loading, empty, failure and expired-report states. Render masked context as text. Preserve null file, line and context values. Display the backend's severity, confidence, rule ID, reason, legal mapping, penalty cap and remediation verbatim where appropriate.
4. Replace fixture imports at each screen boundary with the selected report. Compute filtered counts from its findings and scan-wide totals from its coverage. Populate rule availability from the report and live catalogue. Keep manual checks distinct from detector findings.
5. Keep review state in a separate map keyed by scan and stable finding ID. The demo uses browser storage for synthetic records. Use the team's authorized review persistence for production. Preserve report ownership checks across detail and export routes.
6. Port one route at a time using the [page map](PAGE_SPECIFICATIONS.md). Verify a real successful scan and a real failed scan through the team's existing flow before switching users to the new presentation.

## API connections

| Production target | Prototype replacement |
| --- | --- |
| POST /api/scan | Replace the local submit transition in [Scan.tsx](../frontend/src/Scan.tsx) with the existing ZIP or URL request. Use the returned scan ID. |
| GET /api/scan/{id} | Replace the timer with queued, running, done and failed states. Cancel polling when leaving the view. |
| GET /api/scan/{id}/findings | Supply the dashboard, board, detail and report views from the selected report. Handle unavailable reports explicitly. |
| GET /api/scan/{id}/report.{format} | Use authorized server downloads for supported formats. Prototype JSON includes a sibling review_status map. HTML and SARIF are generated locally. Print / PDF uses the browser print dialog. |
| GET /api/rules | Replace the project-plan catalogue fixture with rule metadata from the server. |
| GET /api/health | Surface service availability through the application's existing health handling. |

Dependencies and pinned resolutions are in [the manifest](../frontend/package.json) and [lockfile](../frontend/package-lock.json). React, React Router, Tailwind, Lucide, Recharts and Motion provide the runtime UI. Vite and TypeScript provide development and build tooling.

When porting the landing page, transfer the SVG, intro and motion styles, shared mark and local font with its license. Mount the intro only on the landing route and preserve the skip control, reduced-motion check and session flag. Carry the shared pixel utility and the dark rail tokens into the corresponding workspace components. [Landing.tsx](../frontend/src/Landing.tsx) · [BrandIntro.tsx](../frontend/src/BrandIntro.tsx) · [Aurora.tsx](../frontend/src/Aurora.tsx) · [Global styles](../frontend/src/styles.css) · [Font assets](../frontend/public/fonts/)

## Acceptance checks

- Compare desktop landing, dashboard and board against the supplied stills. Check narrow screens, keyboard focus, reduced motion, detail dismissal and accessible review controls.
- Trace one line-level, one file-level and one project-wide record through the list, detail and exported report. Confirm masked evidence and source locations survive the adapter.
- Move a card, reload, and compare its scanner fields before and after review. Only review metadata should change.
- Check chart totals against filtered rows and scan coverage against the backend response. Verify unsupported languages and skipped rules are visible.
- Exercise failure, retry and direct-link handling. Confirm exports correspond to the selected scan. Keep the indicative legal-mapping notice on reports.

## Prototype boundaries

All input sources lead to the same 14 synthetic findings for atlas-commerce. The 28 catalogue entries use the project-plan table. Review updates are local to this sample. Remediation is advisory text. Print layout and PDF output depend on the browser. Production scan integration belongs in the team's working application.

## Integration status in the DPDP Auditor repository

The design now runs in the real app under `frontend/` (React 19, Vite 8, react-router 8, Tailwind 4, Recharts 3, lucide-react 0.546.0, motion 12.42.2). The prototype, its fixtures and its simulated scan timer stay in this folder.

| Prototype | Production (`frontend/src/`) | Data source |
| --- | --- | --- |
| `/` Landing, Aurora, BrandIntro | `landing/Landing.tsx`, `landing/Aurora.tsx`, `landing/BrandIntro.tsx`, `landing/*.css` | static product facts; nav follows the last scan |
| `/scan`, `/scan/progress` | `pages/Scan.tsx`: `/scan`, `/scans/:id/progress` | `POST /api/scan`, polling `GET /api/scan/{id}` every second |
| `/dashboard` | `pages/Overview.tsx`: `/scans/:id` | `GET /api/scan/{id}/findings`, loaded once by `pages/ScanLayout.tsx` |
| `/findings`, `/findings/:id` drawer | `pages/Findings.tsx`: `/scans/:id/findings/:findingId?` (one route keeps the board mounted) | same report; review map from `lib/reviews.tsx` |
| detail page | `pages/FindingDetail.tsx` (`FindingView` serves the page and the drawer) | same report |
| `/reports` | `pages/Report.tsx`: `/scans/:id/report` | server downloads `report.{html,pdf,sarif,json}` |
| `/rules` | `pages/Rules.tsx`: `/rules` | `GET /api/rules` |
| `ui.tsx` Shell, Badge, Select | `components/Shell.tsx`, `components/ui.tsx`, `components/ReviewSelect.tsx`, `lib/toast.tsx` | `/api/health` dot in the rail |

Decisions taken during the port:
- Routes are scan-scoped. Rail links follow the scan in the URL, then the last scan opened in the tab (`lib/scope.ts`, memory only), then the bundled sample report (`/scans/sample`, generated from the real models).
- The app has no authentication and no server-side review store. Review status is a separate map per scan and finding id held in memory only (`lib/reviews.tsx`; no localStorage or sessionStorage), labelled "cleared when you reload or leave" wherever it appears. Every finding starts as Open. Server exports never include review state; the report page offers it as a separate "Review notes (JSON)" file.
- Exports are the server's files (masked, authoritative), not locally generated HTML or SARIF. A 501 for PDF (no Pango) is shown in the UI.
- Missing, unfinished and expired reports have explicit states (`ReportError` in `pages/ScanLayout.tsx`); a failed scan names the stage that failed and the server's reason.
- Verified by `frontend/e2e/smoke.mjs`: zip and Git scans, a failed scan, findings and exports, board moves (keyboard select, drag and drop, Undo, reload, scanner fields unchanged), the drawer, keyboard order, the intro and reduced motion, and 390 px layouts on every route.

### Short-lived scans (added after the first integration)

- Scans live 30 minutes (`SCAN_TTL_MINUTES`) and are private to the tab that started them. `lib/session.ts` keeps the scan ids and delete tokens this tab created in memory; on `pagehide` it sends `navigator.sendBeacon` to `POST /api/scans/{id}/delete` (a beacon cannot send DELETE) so the server drops them at once. The server also exposes `DELETE /api/scans/{id}` with the `X-Delete-Token` header; a wrong token is refused (403) and there is no clear-all endpoint.
- After a reload, in a new tab or on a direct link the tab owns nothing, so `api.ts` treats the id as expired (410) without asking the server, and `ReportError` shows "This scan has expired or was not found". A real expiry or deletion answers 410 as well.
- `/scan` lists the saved samples from `GET /api/samples` (reports in `samples/`, outside the TTL, labelled "Saved sample, not a live scan"); `/scans/sample` is the sample bundled in the app for use without a backend.
- Wording: review controls say "cleared when you reload or leave"; the overview says when the server deletes the scan.
- The brand intro keeps its sessionStorage "played" flag: it is a UI preference, not scan data.
