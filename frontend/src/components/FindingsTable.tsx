// The filterable findings table. Filters live in the URL (see lib/findings.ts), so the
// detail screen's "back" link and a copied link show the same view.

import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { applyFilters, compareProvisions, describeLocation, isFiltered, provisionsOf, SEVERITY_LABEL, type Filters } from "../lib/findings";
import type { Finding } from "../types/contract";
import { CONFIDENCES, SEVERITIES } from "../types/contract";
import { ConfidenceTag, SEVERITY_DOT, SeverityBadge } from "./SeverityBadge";

const PAGE = 100;
const EMPTY: Filters = { severities: [], rule: "", provision: "", confidence: "", query: "" };

export function FindingsTable({
  findings,
  filters,
  onChange,
  linkTo,
}: {
  findings: Finding[];
  filters: Filters;
  onChange: (f: Filters) => void;
  linkTo: (f: Finding) => string;
}) {
  const navigate = useNavigate();
  const [limit, setLimit] = useState(PAGE);
  const shown = useMemo(() => applyFilters(findings, filters), [findings, filters]);
  const rules = useMemo(() => countBy(findings.map((f) => f.rule_id)), [findings]);
  const provisions = useMemo(
    () => [...countBy(findings.flatMap(provisionsOf))].sort((a, b) => compareProvisions(a[0], b[0])),
    [findings],
  );
  const titles = useMemo(() => new Map(findings.map((f) => [f.rule_id, f.title])), [findings]);
  const set = (patch: Partial<Filters>) => onChange({ ...filters, ...patch });

  return (
    <div>
      <div className="flex flex-wrap items-end gap-3 border-b border-line px-4 py-3 sm:px-5">
        <label className="min-w-48 flex-1">
          <span className="text-xs font-medium text-muted">Search</span>
          <input
            type="search"
            value={filters.query}
            onChange={(e) => set({ query: e.target.value })}
            placeholder="File, rule or text"
            className="mt-1 block w-full rounded-md border border-line-strong bg-surface px-2.5 py-1.5 text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none"
          />
        </label>
        <div>
          <span className="text-xs font-medium text-muted">Severity</span>
          <div className="mt-1 flex flex-wrap gap-1" role="group" aria-label="Severity">
            {SEVERITIES.map((s) => {
              const on = filters.severities.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  aria-pressed={on}
                  onClick={() => set({ severities: on ? filters.severities.filter((x) => x !== s) : [...filters.severities, s] })}
                  className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1.5 text-xs font-medium transition-colors ${
                    on ? "border-accent bg-accent-soft text-ink" : "border-line-strong text-ink-2 hover:text-ink"
                  }`}
                >
                  <span className={`size-2 rounded-full ${SEVERITY_DOT[s]}`} aria-hidden="true" />
                  {SEVERITY_LABEL[s]}
                </button>
              );
            })}
          </div>
        </div>
        <Select label="Rule" value={filters.rule} onChange={(rule) => set({ rule })}>
          {[...rules].sort().map(([id, n]) => (
            <option key={id} value={id}>{`${id} · ${titles.get(id) ?? ""} (${n})`}</option>
          ))}
        </Select>
        <Select label="Provision" value={filters.provision} onChange={(provision) => set({ provision })}>
          {provisions.map(([p, n]) => (
            <option key={p} value={p}>{`${p} (${n})`}</option>
          ))}
        </Select>
        <Select label="Confidence" value={filters.confidence} onChange={(c) => set({ confidence: c as Filters["confidence"] })}>
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </Select>
      </div>

      <div className="flex items-center justify-between px-4 py-2 text-xs text-muted sm:px-5" aria-live="polite">
        <span className="tabular">
          Showing {shown.length} of {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
        {isFiltered(filters) && (
          <button type="button" onClick={() => onChange(EMPTY)} className="font-medium text-accent hover:underline">
            Clear filters
          </button>
        )}
      </div>

      {shown.length === 0 ? (
        <p className="px-5 pb-8 pt-4 text-center text-sm text-muted">
          {findings.length === 0 ? "The scan reported no findings for the rules it checks." : "No findings match these filters."}
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm md:min-w-[760px]">
            <thead className="border-y border-line bg-surface-2 text-xs text-muted">
              <tr>
                <th scope="col" className="px-4 py-2 font-medium sm:pl-5">Severity</th>
                <th scope="col" className="px-3 py-2 font-medium">Finding</th>
                <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Location</th>
                <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Provision</th>
                <th scope="col" className="hidden px-3 py-2 font-medium sm:pr-5 md:table-cell">Confidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {shown.slice(0, limit).map((f) => (
                <tr
                  key={f.id}
                  onClick={(e) => {
                    if (!(e.target as HTMLElement).closest("a")) navigate(linkTo(f));
                  }}
                  className="cursor-pointer align-top transition-colors hover:bg-surface-2"
                >
                  <td className="px-4 py-3 sm:pl-5">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="px-3 py-3">
                    <Link to={linkTo(f)} className="font-medium text-ink hover:text-accent hover:underline">
                      {f.title}
                    </Link>
                    <p className="mt-0.5 font-mono text-xs text-muted">{f.rule_id}</p>
                    <p className="mt-1 break-all font-mono text-xs text-ink-2 md:hidden">{describeLocation(f)}</p>
                    <p className="mt-1 md:hidden">
                      <ConfidenceTag confidence={f.confidence} />
                    </p>
                  </td>
                  <td className="hidden max-w-72 break-all px-3 py-3 font-mono text-xs text-ink-2 md:table-cell">{describeLocation(f)}</td>
                  <td className="hidden px-3 py-3 text-xs text-ink-2 md:table-cell">
                    {provisionsOf(f).map((p) => (
                      <span key={p} className="mb-1 mr-1 inline-block whitespace-nowrap rounded bg-surface-2 px-1.5 py-0.5">
                        {p}
                      </span>
                    ))}
                  </td>
                  <td className="hidden px-3 py-3 sm:pr-5 md:table-cell">
                    <ConfidenceTag confidence={f.confidence} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length > limit && (
            <div className="border-t border-line px-5 py-3 text-center">
              <button type="button" onClick={() => setLimit(shown.length)} className="text-sm font-medium text-accent hover:underline">
                Show all {shown.length} findings
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Select({ label, value, onChange, children }: { label: string; value: string; onChange: (v: string) => void; children: React.ReactNode }) {
  return (
    <label className="min-w-0 max-w-full">
      <span className="text-xs font-medium text-muted">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 block w-full max-w-64 rounded-md border border-line-strong bg-surface px-2 py-1.5 text-sm text-ink focus:border-accent focus:outline-none"
      >
        <option value="">All</option>
        {children}
      </select>
    </label>
  );
}

function countBy(values: string[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const v of values) counts.set(v, (counts.get(v) ?? 0) + 1);
  return counts;
}
