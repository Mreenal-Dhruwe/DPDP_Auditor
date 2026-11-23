// End-to-end smoke test: drives the real UI in headless Chrome against the live API.
//
//   backend:  uvicorn backend.main:app --port 8000
//   frontend: npm run dev                       (or test the production build on :8000)
//   test:     npm run e2e                       zip upload of target_app
//             npm run e2e -- --git              also scan OWASP Juice Shop from GitHub
//             npm run e2e -- --pdf              PDF export must work (the Docker image); otherwise
//                                               a 501 "no Pango" answer is accepted and its message checked
//             BASE_URL=http://localhost:8000 npm run e2e   (production build served by FastAPI)
//
// Uses playwright-core with the Chrome or Edge already installed (CHROME_PATH overrides),
// so no browser download is needed. Checks: upload -> progress -> dashboard -> detail,
// exports, that the table matches the report, and that no planted secret reaches the page.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const BASE = process.env.BASE_URL ?? "http://localhost:5173";
const WITH_GIT = process.argv.includes("--git");
const NEED_PDF = process.argv.includes("--pdf"); // the Docker image has Pango: PDF must work
const GIT_URL = "https://github.com/juice-shop/juice-shop";

function findBrowser() {
  const candidates = [
    process.env.CHROME_PATH,
    "C:/Program Files/Google/Chrome/Application/chrome.exe",
    "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ];
  const found = candidates.find((c) => c && existsSync(c));
  if (!found) throw new Error("No Chrome/Edge found: set CHROME_PATH");
  return found;
}

/** Secrets planted in the target apps (ground truth "must_not_appear_in_report"). */
function tripwires() {
  const words = [];
  for (const file of ["ground_truth.yml", "ground_truth_js.yml"]) {
    const text = readFileSync(path.join(ROOT, file), "utf8");
    // the top-level key (not the comment that mentions it), up to the next top-level key
    const block = (text.split(/^must_not_appear_in_report:/m)[1] ?? "").split(/^\S/m)[0];
    for (const m of block.matchAll(/^\s+-\s+["']?([^"'\n#]+?)["']?\s*$/gm)) words.push(m[1]);
  }
  if (!words.length) throw new Error("no tripwires found in the ground truth files");
  return words;
}

let failures = 0;
function check(ok, message) {
  console.log(`${ok ? "  ok  " : "  FAIL"} ${message}`);
  if (!ok) failures += 1;
}

async function scanAndCheck(page, start, label, timeoutMs) {
  console.log(`\n${label}`);
  await page.goto(BASE + "/scan");
  await start(page);
  await page.waitForURL(/\/scans\/[^/]+\/progress$/, { timeout: 15000 });
  check(true, "progress view opened");
  await page.waitForURL(/\/scans\/[0-9a-f]{32}$/, { timeout: timeoutMs });
  const scanId = page.url().split("/").pop();
  check(true, `scan finished, dashboard opened (${scanId.slice(0, 8)}…)`);

  const report = await (await page.request.get(`${BASE}/api/scan/${scanId}/findings`)).json();
  await page.waitForSelector("text=Showing");
  const shown = await page.textContent("[aria-live=polite]:has-text('Showing')");
  check(shown.includes(`of ${report.summary.total} finding`), `table counts all ${report.summary.total} findings`);
  for (const [severity, count] of Object.entries(report.summary.by_severity)) {
    const tile = await page.textContent(`button[aria-pressed]:has-text('${severity[0].toUpperCase() + severity.slice(1)}') >> nth=0`);
    check(tile.includes(String(count)), `tile ${severity} shows ${count}`);
  }
  check((await page.locator(".recharts-bar-rectangle").count()) > 0 || report.summary.total === 0, "provision chart drawn");
  check(await page.isVisible("text=rules checked automatically"), "coverage box shown");

  // Filter by the most severe finding's severity, then open it.
  if (report.findings.length) {
    const first = report.findings[0];
    const sevLabel = first.severity[0].toUpperCase() + first.severity.slice(1);
    await page.click(`[aria-label=Severity] button:has-text('${sevLabel}')`);
    check(page.url().includes(`sev=${first.severity}`), "severity filter is kept in the URL");
    await page.click("tbody tr >> nth=0 >> a");
    await page.waitForURL(/\/findings\//);
    check(page.url().includes(first.id), `detail of ${first.rule_id} opened`);
    const titled = await page.waitForSelector(`h1:has-text("${first.title}")`, { timeout: 10000 }).then(() => true, () => false);
    check(titled, "detail title shown"); // the detail screen is a lazily loaded chunk
    check(await page.isVisible("text=Maximum penalty"), "law card shown");
    if (first.context) check((await page.locator("[aria-current=true]").count()) === 1, "flagged line highlighted");

    for (const format of ["json", "html", "sarif"]) {
      const [download] = await Promise.all([
        page.waitForEvent("download", { timeout: 15000 }),
        page.click(`[aria-label='Export the report'] button:has-text('${format.toUpperCase()}')`),
      ]);
      check(download.suggestedFilename().endsWith(`.${format}`), `export ${format} -> ${download.suggestedFilename()}`);
    }
    const pdf = await page.request.get(`${BASE}/api/scan/${scanId}/report.pdf`);
    if (pdf.status() === 501 && !NEED_PDF) {
      await page.click("[aria-label='Export the report'] button:has-text('PDF')");
      const shown = await page.waitForSelector("[role=alert]:has-text('PDF')", { timeout: 10000 }).then(() => true, () => false);
      check(shown, "PDF unavailable (no Pango here): error shown in the UI");
    } else {
      check(pdf.ok(), `PDF from the API (${pdf.status()}${pdf.ok() ? "" : ": " + (await pdf.text()).slice(0, 120)})`);
      if (!pdf.ok()) return { scanId, report };
      const [download] = await Promise.all([
        page.waitForEvent("download", { timeout: 60000 }),
        page.click("[aria-label='Export the report'] button:has-text('PDF')"),
      ]);
      const file = path.join(work, download.suggestedFilename());
      await download.saveAs(file);
      const bytes = readFileSync(file);
      check(bytes.subarray(0, 5).toString() === "%PDF-" && bytes.length > 5000,
        `export pdf -> ${download.suggestedFilename()} (${Math.round(bytes.length / 1024)} KB, valid PDF header)`);
    }
    await page.click("text=all findings");
    await page.waitForURL(/\/scans\/[0-9a-f]{32}\?sev=/);
    check(true, "back link returns to the filtered dashboard");
  }
  return { scanId, report };
}

const work = mkdtempSync(path.join(tmpdir(), "dpdp-e2e-"));
const browser = await chromium.launch({ executablePath: findBrowser() });
try {
  const health = await (await fetch(`${BASE}/api/health`)).json();
  console.log(`API ${health.version}: ${health.rules} rules, ${health.detectors} detectors`);
  const zip = path.join(work, "target_app.zip");
  execFileSync("git", ["-C", ROOT, "archive", "--format=zip", "-o", zip, "HEAD", "target_app"]);

  const page = await browser.newPage({ acceptDownloads: true });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  const secrets = tripwires();
  const noSecrets = async (what) => {
    const html = await page.content();
    check(!secrets.some((s) => html.includes(s)), `no planted secret on the ${what}`);
  };

  const { scanId } = await scanAndCheck(
    page,
    async (p) => {
      await p.setInputFiles("[data-testid=zip-input]", zip);
      check(await p.isVisible("text=target_app.zip"), "zip chosen via the file input");
      await p.click("button[type=submit]");
    },
    "Zip upload: target_app",
    60000,
  );
  await noSecrets("dashboard");
  const report = await (await page.request.get(`${BASE}/api/scan/${scanId}/findings`)).json();
  for (const f of report.findings.filter((x) => x.rule_id === "DPDP-SEC-004")) {
    await page.goto(`${BASE}/scans/${scanId}/findings/${f.id}`);
    await page.waitForSelector("h1");
    await noSecrets(`detail of ${f.rule_id} ${f.file}:${f.line}`);
  }

  if (WITH_GIT) {
    const { report: juice } = await scanAndCheck(
      page,
      async (p) => {
        await p.click("text=Use OWASP Juice Shop");
        await p.click("button[type=submit]");
      },
      `Git URL: ${GIT_URL}`,
      300000,
    );
    console.log(`  Juice Shop: ${juice.summary.total} findings, ${JSON.stringify(juice.summary.by_severity)}`);
  }

  check(errors.length === 0, `no page errors${errors.length ? ": " + errors.join(" | ") : ""}`);
} finally {
  await browser.close();
  rmSync(work, { recursive: true, force: true });
}
console.log(failures ? `\n${failures} check(s) failed` : "\nall checks passed");
process.exit(failures ? 1 : 0);
