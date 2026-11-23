# Demo script (3-4 minutes)

Live scan of **OWASP Juice Shop** from its GitHub URL, then the dashboard, two findings, the
exports, and our accuracy numbers. Words to say are in quotes; actions are in **bold**.

## Before you go on stage (10 minutes earlier)

1. Start the app, one of:
   - Docker: `docker run --rm -p 8000:8000 dpdp-auditor` (PDF export works here)
   - local: `cd frontend && npm run build`, then `uvicorn backend.main:app --port 8000`
2. Open http://localhost:8000 in a clean browser window, zoom to about 125%.
3. **Rehearsal scan:** run one Juice Shop scan now. It checks the network and GitHub; a
   live scan takes about 25-30 s (clone about 6 s, scan about 20 s). Keep that tab open:
   it is backup 1.
4. Open [`samples/juice-shop/report.html`](samples/juice-shop/report.html) in a second tab
   (backup 2, works offline).
5. Have a terminal ready in the project folder with the venv active (backup 3).

## The script

**0:00 - 0:20 The problem**
> "From May 2027, the main duties of the DPDP Rules apply to every app that handles the
> personal data of people in India, and the penalties go up to 250 crore rupees. A developer has no way to see where their code
> breaks the Act. Our auditor reads the code and tells them: the file, the line, the
> section of the Act, how serious it is, and how to fix it."

**0:20 - 0:35 Start the scan**
- **Click "Use OWASP Juice Shop", then "Start scan".**
> "This is OWASP Juice Shop, a real Node and TypeScript shop of about 1,500 files. We only
> read the code: nothing uploaded is ever run, and it is deleted as soon as the scan ends."

**0:35 - 1:00 While it runs (talk over the progress steps)**
> "Fourteen detectors look for personal data (Aadhaar, PAN, phone, email, passwords) and
> check how the code logs it, stores it, sends it and deletes it. Every finding is then
> mapped through one rules file we wrote: 28 rules, each checked against the official
> text of the Act and the Rules. No AI decides anything: the same code always gives the
> same report."

**1:00 - 1:40 The dashboard** (opens by itself when the scan is done)
- **Point at the tiles:** "60 findings: 28 critical, 27 high, the rest medium and info."
- **Point at the chart:** "Almost all of them fall under section 8(5), the duty to protect
  data, which carries the biggest penalty, up to 250 crore."
- **Point at "Scan coverage":** "All 28 rules are checked automatically. Where code can only
  tell part of the story, like whether backups exist, the finding says 'verify manually'."
- **Click the "Critical" tile** to filter the table: "Hard-coded passwords and private keys
  committed to the repository."

**1:40 - 2:40 Two findings**
- **Clear the filter, type `changePassword` in Search, open the finding** (SEC-006,
  `routes/changePassword.ts:56`).
> "When you change your password, Juice Shop sends your whole user record back to the
> browser, password hash included. Here is the code with the line highlighted, the law:
> section 8(5) and Rule 6(1)(a), the penalty cap, why it is rated high, and the fix:
> send only the fields the client needs."
- **Go back, search `user.ts`, open the weak-hashing finding** (SEC-003, `models/user.ts:73`).
> "And passwords are stored as unsalted MD5, which can be cracked in seconds after a leak."
- Optional, if time: **open a `users.yml` finding** and point at `'OhG0********'`.
> "Secrets are masked in every report, so the report never leaks what it found."

**2:40 - 3:05 Exports**
- **Click HTML** (and PDF on Docker).
> "One click for a shareable HTML or PDF report for the compliance team, and SARIF, so the
> same findings show up in GitHub code scanning on every pull request."

**3:05 - 3:40 Does it work? Accuracy and limits**
> "We wrote two deliberately vulnerable apps, one Python and one JavaScript, with an answer
> key of every planted problem and every look-alike that is actually fine. The scanner finds
> all 13 and all 27, with zero false positives, and our 396 tests fail if that ever drops.
> What it cannot do yet: check that a logged-in user only reads their own records, or see
> anything outside the code."

**3:40 - 4:00 Close**
> "So: the file, the line, the section of the Act, the penalty and the fix, in under a
> minute, before the 2027 deadline. Thank you."

## If something goes wrong

| Problem | Do this |
|---|---|
| The scan is slow or the network is down | Switch to the rehearsal tab (backup 1) and say "here is the same scan from a few minutes ago". |
| The server will not start | Open `samples/juice-shop/report.html` (backup 2): same findings, code and law, offline. |
| No browser at all | Terminal: `python -m scanner.cli target_app --out report/` (a few seconds) and walk through the printed findings. |
| PDF answers "not available" | You are not on Docker; show HTML instead: "PDF is enabled in our container image." |
| Someone asks about a finding you cannot explain | Open its detail page: the reason and the law are written there. |

## Numbers to remember
- Juice Shop: 60 findings (28 critical, 27 high, 3 medium, 2 info), about 20 s for 1,494 files
- target_app 13/13, target_app_js 27/27, 0 false positives; 396 tests
- 28 rules, all automated (7 low confidence); severity anchored to the s.33 penalty Schedule (up to Rs 250 crore)
- Rules notified 13 Nov 2025; most apply from 13 May 2027
- "Legal mapping is indicative, not legal advice."
