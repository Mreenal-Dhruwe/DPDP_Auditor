import fixture from "./mock/report.json";
import catalogue from "./mock/rules.json";
export const statuses = ["Open", "Triaged", "In progress", "Resolved"] as const;
export type Status = (typeof statuses)[number];
export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  title: string;
  scope: string;
  file: string | null;
  line: number | null;
  evidence: string;
  context: { start_line: number; lines: string[] } | null;
  pii: string[];
  confidence: string;
  law: { act: string[]; rules: string[]; requirement: string };
  penalty: string;
  severity: string;
  severity_reason: string;
  fix: string;
}
export const report: Omit<typeof fixture, "findings"> & {
  findings: Finding[];
} = fixture;
export const rules = catalogue;
export const levels = ["critical", "high", "medium", "low", "info"];
export function locationOf(f: Finding) {
  return f.file ? f.file + (f.line ? ":" + f.line : "") : "Project-wide";
}
export function countBy(rows: Finding[], key: "severity" | "category") {
  return rows.reduce<Record<string, number>>((counts, f) => {
    counts[f[key]] = (counts[f[key]] ?? 0) + 1;
    return counts;
  }, {});
}
export function provisions(f: Finding) {
  return [...f.law.act, ...f.law.rules].join(" · ");
}
