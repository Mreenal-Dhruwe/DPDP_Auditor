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
// exports, that the table matches the report, and that no planted secret reaches the page;
// a failed scan, the review board (move, in-memory review state, scanner fields unchanged, drag,
// Undo, drawer, cleared on reload), short-lived scans (other visitors, delete token, TTL state,
// saved samples),
// keyboard order, the landing intro and reduced motion, and 390 px layouts on every route.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
    const label = severity[0].toUpperCase() + severity.slice(1);
    const row = await page.getAttribute(`[aria-label='Filter by severity'] button:has-text('${label}')`, "aria-label");
    check(row.startsWith(`${label}: ${count} findings`), `breakdown ${severity} shows ${count}`);
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

// --- extra checks: failure, review board, keyboard, motion, narrow screens ---------------------

/** A tiny zip writer (stored, no compression) so the test needs no zip library. */
function makeZip(entries) {
  const table = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
  });
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (const b of buf) c = table[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, text] of Object.entries(entries)) {
    const data = Buffer.from(text);
    const nameBuf = Buffer.from(name);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, data);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + data.length;
  }
  const dir = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(dir.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, dir, end]);
}

async function failedScan(browser, work) {
  console.log("\nFailed scan: a zip that tries to escape its folder");
  const evil = path.join(work, "evil.zip");
  writeFileSync(evil, makeZip({ "app/main.py": "print(1)\n", "../escape.py": "print(2)\n" }));
  const page = await browser.newPage();
  await page.goto(BASE + "/scan");
  await page.setInputFiles("[data-testid=zip-input]", evil);
  await page.click("button[type=submit]");
  await page.waitForURL(/\/progress$/, { timeout: 15000 });
  const alert = await page.waitForSelector("[role=alert]:has-text('The scan failed')", { timeout: 30000 }).then(() => true, () => false);
  check(alert, "progress view reports the failure");
  check(await page.isVisible("text=unsafe path"), "the server's reason is shown (unsafe path)");
  check(await page.isVisible(".stage.failed"), "the failing stage is marked");
  check(await page.isVisible("a:has-text('Start a new scan')"), "a way to start again is offered");
  await page.close();
}

/** Start a zip scan through the UI in this page and wait for its overview. Returns the scan id. */
async function uiScan(page, zip) {
  await page.goto(BASE + "/scan");
  await page.setInputFiles("[data-testid=zip-input]", zip);
  await page.click("button[type=submit]");
  await page.waitForURL(/\/scans\/[0-9a-f]{32}$/, { timeout: 60000 });
  await page.waitForSelector("text=Showing");
  return page.url().split("/").pop();
}

/** Navigate inside the app without reloading: a reload would (by design) delete this tab's scans. */
async function spaGo(page, route) {
  await page.evaluate((r) => {
    history.pushState({}, "", r);
    window.dispatchEvent(new PopStateEvent("popstate"));
  }, route);
  await page.waitForTimeout(500);
}

const EXPIRED = "text=This scan has expired or was not found";

async function reviewBoard(browser, zip) {
  console.log("\nReview board: move, navigate, scanner fields unchanged, cleared on reload");
  // tall viewport: the card and the target column both on screen, so nothing scrolls mid-drag
  const context = await browser.newContext({ viewport: { width: 1440, height: 1800 } });
  const page = await context.newPage();
  const scanId = await uiScan(page, zip);
  const report = await (await page.request.get(`${BASE}/api/scan/${scanId}/findings`)).json();
  const card = report.findings[0];
  await page.click("[aria-label='Workspace'] a[aria-label='Findings']");
  const select = `[aria-label="Review status for ${card.title}"]`;
  await page.waitForSelector(select);
  // keyboard: focus the card's status select and change it
  await page.focus(select);
  await page.selectOption(select, "Triaged");
  const toast = await page.waitForSelector(".toast:has-text('moved to Triaged')", { timeout: 5000 }).then(() => true, () => false);
  check(toast, "moving a card announces it with Undo");
  const column = await page.textContent(`.column:has(h2:has-text('Triaged')) .stack`);
  check(column.includes(card.title), "the card is now in the Triaged column");
  // moving between screens keeps the in-memory review state
  await page.click("[aria-label='Workspace'] a[aria-label='Overview']");
  await page.waitForSelector("text=Showing");
  await page.click("[aria-label='Workspace'] a[aria-label='Findings']");
  await page.waitForSelector(select);
  check((await page.inputValue(select)) === "Triaged", "review status survives moving between screens (memory only)");
  const after = await (await page.request.get(`${BASE}/api/scan/${scanId}/findings`)).json();
  check(JSON.stringify(after.findings[0]) === JSON.stringify(card), "scanner fields (severity, confidence, law, evidence) unchanged after the move");
  // drag and drop with a real pointer
  const other = report.findings[1];
  const source = page.locator(".finding-card", { hasText: other.title }).first();
  // aim at the top of the column: scrolling a tall target mid-drag would move the page under the pointer
  await source.dragTo(page.locator(".column:has(h2:has-text('In progress')) .stack"), { targetPosition: { x: 40, y: 24 } });
  const moved = await page.waitForFunction((title) => document.querySelector(`.column:nth-child(3) [aria-label="Review status for ${title}"]`)?.value === "In progress", other.title, { timeout: 3000 }).then(() => true, () => false);
  check(moved, "drag and drop moves a card to In progress");
  await page.click(".toast:has-text('In progress') button:has-text('Undo')");
  check((await page.inputValue(`[aria-label="Review status for ${other.title}"]`)) === "Open", "Undo puts it back");
  // evidence drawer
  await page.click(`.cardtitle:has-text("${card.title}")`);
  const drawer = await page.waitForSelector("dialog.drawer[open]", { timeout: 5000 }).then(() => true, () => false);
  check(drawer, "opening a card shows the evidence drawer");
  check(await page.isVisible("dialog.drawer >> text=Maximum penalty"), "the drawer shows the legal mapping");
  await page.keyboard.press("Escape");
  await page.waitForURL(/\/findings$/, { timeout: 5000 });
  check(!(await page.isVisible("dialog.drawer[open]")), "Escape closes the drawer and returns to the board");
  // memory only: nothing about scans or reviews is written to browser storage
  const storage = await page.evaluate(() => ({ local: localStorage.length, session: Object.keys(sessionStorage) }));
  check(storage.local === 0 && storage.session.every((k) => k === "dpdp.brand-intro"), `no review state or scan ids in browser storage (${JSON.stringify(storage)})`);
  // a reload starts empty: the scan is gone and so are the reviews
  await page.reload();
  check(await page.waitForSelector(EXPIRED, { timeout: 8000 }).then(() => true, () => false), "after a reload the same link shows the expired or not-found state");
  check((await page.locator(".finding-card").count()) === 0, "a reload brings back no cards and no review state");
  await context.close();
}

async function keyboardAndMotion(browser, scanId) {
  console.log("\nKeyboard, intro and reduced motion");
  const motion = await browser.newContext();
  let page = await motion.newPage();
  await page.goto(BASE + "/");
  const intro = await page.waitForSelector(".brand-intro", { timeout: 3000 }).then(() => true, () => false);
  check(intro, "the brand intro plays on the first landing visit");
  await page.keyboard.press("Escape");
  check((await page.locator(".brand-intro").count()) === 0, "Escape skips the intro");
  check(await page.isVisible("button[aria-label='Pause landing animations']"), "the marquee has a pause control");
  await page.click("button[aria-label='Pause landing animations']");
  const state = await page.$eval(".capability-track", (el) => getComputedStyle(el).animationPlayState);
  check(state === "paused", "pause stops the marquee");
  await page.goto(BASE + "/");
  check((await page.locator(".brand-intro").count()) === 0, "the intro plays once per session");
  await page.goto(`${BASE}/scans/${scanId}`);
  await page.waitForSelector("h1");
  await page.keyboard.press("Tab");
  check((await page.evaluate(() => document.activeElement?.textContent)) === "Skip to content", "the first Tab reaches the skip link");
  await page.keyboard.press("Tab");
  check((await page.evaluate(() => document.activeElement?.getAttribute("aria-label"))) === "DPDP Auditor home", "then the rail");
  await motion.close();

  const reduced = await browser.newContext({ reducedMotion: "reduce" });
  page = await reduced.newPage();
  await page.goto(BASE + "/");
  await page.waitForSelector("text=From repository to compliance report");
  check((await page.locator(".brand-intro").count()) === 0, "reduced motion: no intro");
  check(!(await page.isVisible("button[aria-label='Pause landing animations']")), "reduced motion: nothing moves, so no pause control");
  check((await page.locator(".capability-set").first().isVisible()) && !(await page.locator(".capability-set[aria-hidden]").isVisible()), "reduced motion: one static capability list");
  await reduced.close();
}

async function narrowScreens(browser, zip) {
  console.log("\nNarrow screens (390 px): no sideways scrolling");
  const context = await browser.newContext({ viewport: { width: 390, height: 844 }, reducedMotion: "reduce" });
  const page = await context.newPage();
  const scanId = await uiScan(page, zip);
  const report = await (await page.request.get(`${BASE}/api/scan/${scanId}/findings`)).json();
  const findingId = report.findings[0].id;
  for (const route of [`/scans/${scanId}`, "/scan", `/scans/${scanId}/findings`, `/scans/${scanId}/findings/${findingId}`, `/scans/${scanId}/report`, "/rules", "/"]) {
    await spaGo(page, route); // in-app navigation: a reload would delete the scan
    await page.waitForLoadState("networkidle");
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(overflow <= 0, `${route.replace(scanId, "<scan>").replace(findingId, "<finding>")} fits a 390 px screen`);
  }
  await context.close();
}

async function expiryAndPrivacy(browser, zip) {
  console.log("\nShort-lived scans: other visitors, delete token, reload, saved samples");
  const health = await (await fetch(`${BASE}/api/health`)).json();
  check(health.scan_ttl_minutes > 0, `the server reports its scan TTL (${health.scan_ttl_minutes} min)`);

  const a = await browser.newContext();
  const pageA = await a.newPage();
  const scanId = await uiScan(pageA, zip);
  check(await pageA.isVisible("text=deleted from the server"), "the overview says when the scan is deleted");

  // another visitor (a new browser context = a new tab / person) opens the link directly
  const b = await browser.newContext();
  const pageB = await b.newPage();
  await pageB.goto(`${BASE}/scans/${scanId}`);
  check(await pageB.waitForSelector(EXPIRED, { timeout: 8000 }).then(() => true, () => false), "a direct visit to the link shows the expired or not-found state");
  check((await pageB.locator("table").count()) === 0 && !(await pageB.isVisible("text=Hardcoded secrets")), "...and none of the report");
  await pageB.goto(`${BASE}/scans/${scanId}/progress`);
  check(await pageB.waitForSelector("text=This scan has expired or was not found", { timeout: 8000 }).then(() => true, () => false), "a direct visit to the progress link shows it too");

  // the delete token is per scan: no token, a wrong token and another scan's token are refused
  for (const [what, headers] of [["no token", {}], ["a wrong token", { "X-Delete-Token": "wrong" }]]) {
    const response = await pageB.request.delete(`${BASE}/api/scans/${scanId}`, { headers });
    check(response.status() === 403, `DELETE with ${what} is refused (403)`);
  }
  check((await pageB.request.get(`${BASE}/api/scan/${scanId}/findings`)).status() === 200, "...and the scan is still there");
  check([404, 405].includes((await pageB.request.delete(`${BASE}/api/scans`)).status()), "there is no clear-all endpoint");

  // the owner reloads: the page-leave beacon deletes the scan right away
  await pageA.reload();
  check(await pageA.waitForSelector(EXPIRED, { timeout: 8000 }).then(() => true, () => false), "the owner's reload shows the expired state too");
  let status = 0;
  for (let i = 0; i < 20 && status !== 410; i++) {
    status = (await pageB.request.get(`${BASE}/api/scan/${scanId}/findings`)).status();
    if (status !== 410) await pageB.waitForTimeout(250);
  }
  check(status === 410, "leaving the page deleted the scan on the server (410)");

  // saved samples: loadable any time, clearly labelled, never tied to a tab
  await pageB.goto(BASE + "/scan");
  await pageB.waitForSelector("#samples a");
  const names = await pageB.$$eval("#samples strong", (e) => e.map((x) => x.textContent));
  check(["target_app", "target_app_js", "juice-shop"].every((n) => names.includes(n)), `saved samples are listed (${names.join(", ")})`);
  check(await pageB.isVisible("#samples >> text=not live scans"), "the list says they are saved samples, not live scans");
  await pageB.click("#samples a:has-text('juice-shop')");
  await pageB.waitForSelector("text=Showing");
  check(await pageB.isVisible("text=Saved sample, not a live scan"), "a saved sample is labelled on its overview");
  await pageB.reload();
  check(await pageB.waitForSelector("text=Saved sample, not a live scan", { timeout: 8000 }).then(() => true, () => false), "a saved sample still loads after a reload");
  const sampleExport = await pageB.request.get(`${BASE}/api/samples/juice-shop/report.html`);
  check(sampleExport.ok(), "saved samples can be exported");
  await a.close();
  await b.close();
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
    await spaGo(page, `/scans/${scanId}/findings/${f.id}`); // not goto: a reload would delete the scan
    await page.waitForSelector("h1");
    await noSecrets(`detail of ${f.rule_id} ${f.file}:${f.line}`);
  }

  await failedScan(browser, work);
  await reviewBoard(browser, zip);
  await keyboardAndMotion(browser, scanId);
  await narrowScreens(browser, zip);
  await expiryAndPrivacy(browser, zip);

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
