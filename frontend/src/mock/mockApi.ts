// Simulated API for `npm run dev:mock` ONLY (VITE_API_MODE=mock, no backend needed).
//
// This module and mock/report.json are imported only behind a MOCK_MODE check in api.ts,
// which is a build-time constant: a production build never includes either of them, and a
// normal session never loads a report by default.

import { registerScan } from "../lib/session";
import type { Report, ScanStarted, ScanStatus } from "../types/contract";
import mockReportJson from "./report.json";

const report = mockReportJson as Report;
const STEP_MS = 900;
const scans = new Map<string, { target: string; source: "zip" | "git"; started: number }>();
const STEPS = {
  zip: ["queued", "unpacking", "scanning", "writing reports", "done"],
  git: ["queued", "cloning", "scanning", "writing reports", "done"],
};

export const mockReport = (): Report => report;

export function mockStart(target: string, source: "zip" | "git"): Promise<ScanStarted> {
  const scanId = `mock-${Date.now().toString(36)}`;
  scans.set(scanId, { target, source, started: Date.now() });
  registerScan(scanId, "mock");
  return new Promise((resolve) => setTimeout(() => resolve({ scan_id: scanId, delete_token: "mock" }), 300));
}

export function mockStatus(scanId: string): ScanStatus {
  const scan = scans.get(scanId) ?? { target: report.target, source: "zip" as const, started: 0 };
  const steps = STEPS[scan.source];
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
    expires_at: new Date((scan.started || Date.now()) + 30 * 60_000).toISOString(),
    finished_at: done ? new Date().toISOString() : null,
    error: null,
    summary: done ? report.summary : null,
  };
}

/** One listed sample so /samples has something to show without a backend. */
export const mockSamples = () => [
  {
    id: "sample-target_app",
    name: "target_app",
    target: report.target,
    total: report.summary.total,
    by_severity: report.summary.by_severity,
    generated_at: report.generated_at,
  },
];
