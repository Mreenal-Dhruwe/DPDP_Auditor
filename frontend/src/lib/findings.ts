// Helpers shared by the dashboard and the detail screen: locations, provisions and the
// findings filter (kept in the URL so "back" and shared links keep the same view).

import type { Confidence, Finding, Severity } from "../types/contract";
import { CONFIDENCES, SEVERITIES } from "../types/contract";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Same text as describe_location() in scanner/models.py. */
export function describeLocation(f: Pick<Finding, "scope" | "file" | "line">): string {
  const where = f.line !== null ? `${f.file}:${f.line}` : f.file;
  if (f.scope === "project") return where ? `project-wide (see ${where})` : "project-wide";
  return where ?? "";
}

/** Act sections first, then Rules: "s.8(5)", "Rule 6(1)(a)". */
export function provisionsOf(f: Finding): string[] {
  return [...f.law.act, ...f.law.rules];
}

export interface Filters {
  severities: Severity[]; // empty = all
  rule: string;
  provision: string;
  confidence: Confidence | "";
  category: string; // "Security", "Consent" ... (the rule's category)
  query: string; // matches file, title, rule id or evidence
}

export function readFilters(params: URLSearchParams): Filters {
  const sev = (params.get("sev") ?? "").split(",").filter((s): s is Severity => (SEVERITIES as readonly string[]).includes(s));
  const conf = params.get("conf") ?? "";
  return {
    severities: sev,
    rule: params.get("rule") ?? "",
    provision: params.get("prov") ?? "",
    confidence: (CONFIDENCES as readonly string[]).includes(conf) ? (conf as Confidence) : "",
    category: params.get("cat") ?? "",
    query: params.get("q") ?? "",
  };
}

export function writeFilters(filters: Filters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.severities.length) params.set("sev", filters.severities.join(","));
  if (filters.rule) params.set("rule", filters.rule);
  if (filters.provision) params.set("prov", filters.provision);
  if (filters.confidence) params.set("conf", filters.confidence);
  if (filters.category) params.set("cat", filters.category);
  if (filters.query.trim()) params.set("q", filters.query); // untrimmed: the user may still be typing
  return params;
}

export function isFiltered(f: Filters): boolean {
  return writeFilters(f).toString() !== "";
}

export function applyFilters(findings: Finding[], f: Filters): Finding[] {
  const q = f.query.trim().toLowerCase();
  return findings.filter(
    (x) =>
      (!f.severities.length || f.severities.includes(x.severity)) &&
      (!f.rule || x.rule_id === f.rule) &&
      (!f.provision || provisionsOf(x).includes(f.provision)) &&
      (!f.confidence || x.confidence === f.confidence) &&
      (!f.category || x.category === f.category) &&
      (!q || [x.file ?? "", x.title, x.rule_id, x.evidence, x.category].some((s) => s.toLowerCase().includes(q))),
  );
}

/** "s.8(5)" before "s.16(1)" before "Rule 3(c)(i)": Act first, then numeric order. */
export function compareProvisions(a: string, b: string): number {
  const key = (p: string) => [p.startsWith("Rule") ? 1 : 0, Number(/\d+/.exec(p)?.[0] ?? 0)] as const;
  const [ka, kb] = [key(a), key(b)];
  return ka[0] - kb[0] || ka[1] - kb[1] || a.localeCompare(b);
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? iso
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export const EMPTY_FILTERS: Filters = { severities: [], rule: "", provision: "", confidence: "", category: "", query: "" };

/** Counts per key, most common first: countBy(findings, (f) => f.category). */
export function countBy<T>(items: T[], key: (item: T) => string | string[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const keys = key(item);
    for (const k of Array.isArray(keys) ? keys : [keys]) counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

/** "full_name" -> "full name" for display. */
export const piiLabel = (label: string) => label.replaceAll("_", " ");
