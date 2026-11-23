// Typed calls to the FastAPI backend (/api, proxied by Vite in development).
//
// Two ways to run without a backend:
// - `npm run dev:mock` (VITE_API_MODE=mock): scans are simulated step by step and every
//   report is src/mock/report.json.
// - the scan id "sample" always shows that mock report, in any mode: an offline demo.

import type { Report, ScanStarted, ScanStatus, Severity } from "./types/contract";

export const MOCK_MODE = import.meta.env.VITE_API_MODE === "mock";
export const SAMPLE_ID = "sample";
export const EXPORT_FORMATS = ["html", "pdf", "sarif", "json"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** The sample report, loaded only when needed (it is a separate chunk of the build). */
const loadSample = () => import("./mock/report.json").then((m) => m.default as Report);

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** FastAPI errors look like {"detail": "..."}; show that text, not the status code. */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, init);
  } catch {
    throw new ApiError(0, "Cannot reach the scanner API. Is the backend running on port 8000?");
  }
  if (!response.ok) throw new ApiError(response.status, await errorText(response));
  return (await response.json()) as T;
}

async function errorText(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    /* not JSON */
  }
  return `${response.status} ${response.statusText || "error"}`;
}

// --- starting a scan -------------------------------------------------------------------

export function startZipScan(file: File): Promise<ScanStarted> {
  if (MOCK_MODE) return mockStart(file.name.replace(/\.zip$/i, ""), "zip");
  const form = new FormData();
  form.append("file", file);
  return request<ScanStarted>("/api/scan", { method: "POST", body: form });
}

export function startGitScan(gitUrl: string): Promise<ScanStarted> {
  if (MOCK_MODE) return mockStart(gitUrl.split("/").pop()?.replace(/\.git$/, "") || "repo", "git");
  return request<ScanStarted>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ git_url: gitUrl }),
  });
}

export function getScanStatus(scanId: string): Promise<ScanStatus> {
  if (MOCK_MODE || scanId === SAMPLE_ID) return loadSample().then((sample) => mockStatus(scanId, sample));
  return request<ScanStatus>(`/api/scan/${encodeURIComponent(scanId)}`);
}

// --- reports ---------------------------------------------------------------------------

const reports = new Map<string, Promise<Report>>(); // a finished report never changes

export function getReport(scanId: string): Promise<Report> {
  if (MOCK_MODE || scanId === SAMPLE_ID) return loadSample();
  let pending = reports.get(scanId);
  if (!pending) {
    pending = request<Report>(`/api/scan/${encodeURIComponent(scanId)}/findings`);
    pending.catch(() => reports.delete(scanId)); // retry later, e.g. after a 409 "still running"
    reports.set(scanId, pending);
  }
  return pending;
}

/** Exports are only offline for JSON: the other formats are rendered by the backend. */
export function canExport(scanId: string, format: ExportFormat): boolean {
  return format === "json" || !(MOCK_MODE || scanId === SAMPLE_ID);
}

/** Download a report file. Fetched first (not a plain link) so errors such as
 *  "PDF needs the Pango libraries" (501) can be shown instead of a broken download. */
export async function downloadReport(scanId: string, format: ExportFormat, target: string): Promise<void> {
  const fallbackName = `dpdp-report-${target}.${format}`;
  if (MOCK_MODE || scanId === SAMPLE_ID) {
    if (format !== "json") throw new ApiError(0, "Run a real scan to export this format.");
    saveBlob(new Blob([JSON.stringify(await loadSample(), null, 2)], { type: "application/json" }), fallbackName);
    return;
  }
  let response: Response;
  try {
    response = await fetch(`/api/scan/${encodeURIComponent(scanId)}/report.${format}`);
  } catch {
    throw new ApiError(0, "Cannot reach the scanner API.");
  }
  if (!response.ok) throw new ApiError(response.status, await errorText(response));
  const named = /filename="?([^";]+)"?/.exec(response.headers.get("content-disposition") ?? "")?.[1];
  saveBlob(await response.blob(), named ?? fallbackName);
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// --- mock scans (npm run dev:mock) -------------------------------------------------------

const STEP_MS = 900;
const mockScans = new Map<string, { target: string; source: "zip" | "git"; started: number }>();
const MOCK_STEPS = { zip: ["queued", "unpacking", "scanning", "writing reports", "done"], git: ["queued", "cloning", "scanning", "writing reports", "done"] };

function mockStart(target: string, source: "zip" | "git"): Promise<ScanStarted> {
  const scanId = `mock-${Date.now().toString(36)}`;
  mockScans.set(scanId, { target, source, started: Date.now() });
  return new Promise((resolve) => setTimeout(() => resolve({ scan_id: scanId }), 300));
}

function mockStatus(scanId: string, sample: Report): ScanStatus {
  const scan = mockScans.get(scanId) ?? { target: sample.target, source: "zip" as const, started: 0 };
  const steps = MOCK_STEPS[scan.source];
  const index = Math.min(steps.length - 1, Math.floor((Date.now() - scan.started) / STEP_MS));
  const done = index === steps.length - 1;
  return {
    scan_id: scanId,
    target: scan.target,
    source: scan.source,
    status: done ? "done" : index === 0 ? "queued" : "running",
    step: steps[index],
    steps,
    created_at: new Date(scan.started || Date.now()).toISOString(),
    finished_at: done ? new Date().toISOString() : null,
    error: null,
    summary: done ? sample.summary : null,
  };
}

// --- rule catalogue and service health -----------------------------------------------------

/** One rule as GET /api/rules returns it (rules/dpdp_rules.yml, the source of legal meaning). */
export interface RuleInfo {
  id: string;
  category: string;
  title: string;
  detects: string[];
  targets: string[];
  law: { act: string[]; rules: string[]; requirement: string };
  penalty: string; // a key of `penalty_caps`
  severity: Severity;
  severity_reason: string;
  fix: string;
}
export interface Catalogue {
  rules: RuleInfo[];
  checked: string[]; // rule ids with an automated detector
  penalty_caps: Record<string, { schedule_item: number; provision: string; cap: string }>;
}

let catalogue: Promise<Catalogue> | null = null;

/** The live rule catalogue. Mock mode has no backend, so it fails with a clear message. */
export function getCatalogue(): Promise<Catalogue> {
  if (MOCK_MODE) return Promise.reject(new ApiError(0, "The rule catalogue comes from the API; mock mode has none."));
  catalogue ??= request<Catalogue>("/api/rules");
  catalogue.catch(() => (catalogue = null)); // retry on the next call
  return catalogue;
}

/** {rule id: title}, or {} when the catalogue is unavailable. */
export function getRuleTitles(): Promise<Record<string, string>> {
  return getCatalogue().then(
    (c) => Object.fromEntries(c.rules.map((r) => [r.id, r.title])),
    () => ({}),
  );
}

export interface Health {
  status: string;
  version: string;
  rules: number;
  detectors: number;
  rules_checked: number;
}

export function getHealth(): Promise<Health> {
  if (MOCK_MODE) return Promise.reject(new ApiError(0, "mock mode"));
  return request<Health>("/api/health");
}
