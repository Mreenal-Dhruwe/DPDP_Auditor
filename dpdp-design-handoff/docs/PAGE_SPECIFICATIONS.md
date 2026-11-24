# Page specifications

| Route | Layout and behavior |
| --- | --- |
| `/` | Floating rounded navigation with a glass hover capsule, three-line headline clipped by the aurora, synchronized strand pulses and headline color, right-side copy and two actions, left-to-right capability marquee, pastel three-column panel. Start a scan opens ingestion. View demo opens the sample overview. |
| `/scan` | Archive and Git URL modes share a form. Pick or drop a non-empty ZIP, or enter an HTTPS repository URL. Validation precedes navigation. Only the source label and start time enter route state. |
| `/scan/progress` | Six timed stages with completion, cancel and automatic routing. A direct visit without a source explains how to restart. |
| `/dashboard` | Confidence comparison by severity, category bar chart, dark two-by-two summary, light coverage/profile/review band, findings table. Category selection filters findings and charts. File and rule totals retain scan scope. |
| `/findings` | Four review columns with stable finding IDs, severity labels, file metadata and a status selector. Search titles, rules, paths or provisions. Switch to a list or filter by severity. Dragging changes review status. |
| `/findings/:id` | Opening a board card displays a right-hand evidence dialog. Direct links render a full page. Show actual scope, masked context and line numbers when present, law, indicative cap, rationale and recommendation. |
| `/reports` | Sample report summary, severity distribution, mapped provisions, coverage, manual checks and downloads. The print stylesheet expands individual findings. |
| `/rules` | Catalogue from the project-plan rule table with demo execution, skipped and manual-review filters. |

## Reference checks

- Match the clipped lettering, whitespace and relative placement of the two calls to action to [the landing reference](../references/nice_front_page.webp).
- Use the current landing capture for composition, the supporting copy capture for body typography, and the Block Craft example for the pixel accent. [Landing capture](<../references/Screenshot 2026-11-23 234041.png>) · [Supporting copy](<../references/Screenshot 2026-11-23 234833.png>) · [Pixel font sample](<../references/Screenshot 2026-11-23 234746.png>)
- Compare the charts, grouped metrics, compact rail proportions and light lower band with the dashboard reference. Use the dark rail palette from the design system for every workspace route. [Dashboard reference](<../references/Screenshot 2026-11-23 211559.png>)
- Use [the supplied board still](<../references/Screenshot 2026-11-23 222506.png>) for column gutters, compact cards and metadata hierarchy. Match the lift, insertion cue and side detail interaction from [the motion reference](../references/reference.mp4).
- Preserve the fields, scopes and rule coverage described in [the project plan](<../references/DPDP Compliance Auditor — Complete Project Plan.docx>). The sample report was created for this prototype.

## Production routes (frontend/)

| Route | Layout and behavior |
| --- | --- |
| `/` | As above. "Start a scan" opens `/scan`; "View saved samples" opens `/samples`; nav links are New scan, Saved samples and Rules. No report is loaded on the landing page. The pastel panel states product facts (28 rules, 3 evidence scopes, 0 lines executed). The footer carries the disclaimer. |
| `/scan` | ZIP or Git URL tabs, a dropzone with a keyboard-focusable input, URL checks matching the backend's, a Juice Shop shortcut and a "How the scan runs" aside. |
| `/scans/:id/progress` | Real stages from `GET /api/scan/{id}`. A failure names the stage and the server's reason; an unknown scan explains that restarts forget scans. Opens the overview when done. |
| `/scans/:id` | Overview: severity × confidence breakdown (rows filter), provision chart, 2×2 summary (in-view and scan-wide numbers labelled), light band (coverage, personal data exposed, review queue), findings table. The category select filters the page. |
| `/scans/:id/findings` | Board or list (`?view=list`), search, severity chips and confidence. Cards show the severity badge and edge stripe, rule id, title, location, confidence and review select. |
| `/scans/:id/findings/:fid` | From the board: a drawer over the board. Direct link: a full page with a back link to the filtered overview. Previous / next follow the current filters. |
| `/scans/:id/report` | Report header, severity distribution, provisions, categories, coverage and low-confidence findings to verify, server downloads, review progress and the review notes JSON. |
| `/rules` | Live catalogue with search and a category filter; rule ids on findings link here. |
| `/samples` | The saved sample reports as cards (target, findings, severities, save date), each labelled "Saved sample, not your scan". The only listing; fetched from `GET /api/samples`. |
| `/samples/:name`, `/samples/:name/findings`, `/samples/:name/report` | The same screens as a scan, under a sample banner ("Saved sample, not your scan") on every one; never described as expiring. An unknown name shows "Saved sample not found". |
