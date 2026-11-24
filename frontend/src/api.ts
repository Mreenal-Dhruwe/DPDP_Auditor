// Typed calls to the FastAPI backend (/api, proxied by Vite in development).
//
// No report is ever loaded by default: reports come from the API only when a visitor starts
// a scan or opens a saved sample. `npm run dev:mock` (VITE_API_MODE=mock) simulates the API
// from src/mock/mockApi.ts; MOCK_MODE is a build-time constant, so a production build does not
// contain that module or src/mock/report.json.

import { isSampleId, ownsScan, registerScan } from "./lib/session";
import type { Report, ScanStarted, ScanStatus, Severity } from "./types/contract";

export const MOCK_MODE = import.meta.env.VITE_API_MODE === "mock";
export const EXPORT_FORMATS = ["html", "pdf", "sarif", "json"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

/** Development only: reached solely through `if (MOCK_MODE)`, which is dead code in production. */
const mockApi = () => import("./mock/mockApi");

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

/** The tab keeps the delete token (in memory) so it can delete the scan when the page is left. */
const registered = (started: ScanStarted) => {
  registerScan(started.scan_id, started.delete_token);
  return started;
};

export function startZipScan(file: File): Promise<ScanStarted> {
  if (MOCK_MODE) return mockApi().then((m) => m.mockStart(file.name.replace(/\.zip$/i, ""), "zip"));
  const form = new FormData();
  form.append("file", file);
  return request<ScanStarted>("/api/scan", { method: "POST", body: form }).then(registered);
}

export function startGitScan(gitUrl: string): Promise<ScanStarted> {
  if (MOCK_MODE) return mockApi().then((m) => m.mockStart(gitUrl.split("/").pop()?.replace(/\.git$/, "") || "repo", "git"));
  return request<ScanStarted>("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ git_url: gitUrl }),
  }).then(registered);
}

/** Scans belong to the tab that started them. After a reload, in a new tab or on a direct
 *  visit this tab owns nothing, so a scan id is treated exactly like an expired one (410),
 *  without asking the server. */
function requireOwned(scanId: string): void {
  if (!isSampleId(scanId) && !ownsScan(scanId))
    throw new ApiError(410, "This scan was started in another tab or before a reload. Scans are cleared when you reload or leave.");
}

export function getScanStatus(scanId: string): Promise<ScanStatus> {
  if (MOCK_MODE) return mockApi().then((m) => m.mockStatus(scanId));
  try {
    requireOwned(scanId);
  } catch (e) {
    return Promise.reject(e);
  }
  return request<ScanStatus>(`/api/scan/${encodeURIComponent(scanId)}`);
}

// --- saved samples: reports made earlier by the command line, served by the API, never expire ---

export interface SampleInfo {
  id: string; // "sample-<name>"
  name: string;
  target: string;
  total: number;
  by_severity: Record<Severity, number>;
  generated_at: string;
}

export function getSamples(): Promise<SampleInfo[]> {
  if (MOCK_MODE) return mockApi().then((m) => m.mockSamples());
  return request<SampleInfo[]>("/api/samples");
}

const sampleName = (scanId: string) => encodeURIComponent(scanId.slice("sample-".length));

// --- reports ---------------------------------------------------------------------------

// No cache: a scan can expire on the server, so every visit to a report asks again.
export function getReport(scanId: string): Promise<Report> {
  if (MOCK_MODE) return mockApi().then((m) => m.mockReport());
  if (isSampleId(scanId)) return request<Report>(`/api/samples/${sampleName(scanId)}/findings`);
  try {
    requireOwned(scanId);
  } catch (e) {
    return Promise.reject(e);
  }
  return request<Report>(`/api/scan/${encodeURIComponent(scanId)}/findings`);
}

/** In mock mode only JSON can be exported: the other formats are rendered by the backend. */
export function canExport(_scanId: string, format: ExportFormat): boolean {
  return format === "json" || !MOCK_MODE;
}

/** Download a report file. Fetched first (not a plain link) so errors such as
 *  "PDF needs the Pango libraries" (501) can be shown instead of a broken download. */
export async function downloadReport(scanId: string, format: ExportFormat, target: string): Promise<void> {
  const fallbackName = `dpdp-report-${target}.${format}`;
  if (MOCK_MODE) {
    if (format !== "json") throw new ApiError(0, "Run a real scan to export this format.");
    saveBlob(new Blob([JSON.stringify((await mockApi()).mockReport(), null, 2)], { type: "application/json" }), fallbackName);
    return;
  }
  let response: Response;
  try {
    const base = isSampleId(scanId) ? `/api/samples/${sampleName(scanId)}` : `/api/scan/${encodeURIComponent(scanId)}`;
    response = await fetch(`${base}/report.${format}`);
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
