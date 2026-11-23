// Filterable findings table (overview). Filters live in the URL (lib/findings.ts), so links,
// "back" from a finding and shared URLs keep the same view.

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";
import { applyFilters, compareProvisions, countBy, describeLocation, EMPTY_FILTERS, isFiltered, provisionsOf, SEVERITY_LABEL, type Filters } from "../lib/findings";
import { useReviews } from "../lib/reviews";
import type { Finding } from "../types/contract";
import { CONFIDENCES, SEVERITIES } from "../types/contract";
import { ConfidenceMeter, SeverityBadge } from "./ui";

const PAGE = 100;

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
  const { statusOf } = useReviews();
  const [limit, setLimit] = useState(PAGE);
  const shown = useMemo(() => applyFilters(findings, filters), [findings, filters]);
  const rules = useMemo(() => countBy(findings, (f) => f.rule_id).sort((a, b) => a[0].localeCompare(b[0])), [findings]);
  const provisions = useMemo(() => countBy(findings, provisionsOf).sort((a, b) => compareProvisions(a[0], b[0])), [findings]);
  const titles = useMemo(() => new Map(findings.map((f) => [f.rule_id, f.title])), [findings]);
  const set = (patch: Partial<Filters>) => onChange({ ...filters, ...patch });

  return (
    <div className="findings-table">
      <div className="toolbar">
        <label className="search">
          <Search size={16} aria-hidden="true" />
          <input type="search" aria-label="Search findings" placeholder="Search file, rule or text" value={filters.query} onChange={(e) => set({ query: e.target.value })} />
        </label>
        <div className="sevchips" role="group" aria-label="Severity">
          {SEVERITIES.map((s) => {
            const on = filters.severities.includes(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                className={`sev-${s}`}
                onClick={() => set({ severities: on ? filters.severities.filter((x) => x !== s) : [...filters.severities, s] })}
              >
                <i aria-hidden="true" />
                {SEVERITY_LABEL[s]}
              </button>
            );
          })}
        </div>
        <select aria-label="Rule" value={filters.rule} onChange={(e) => set({ rule: e.target.value })}>
          <option value="">All rules</option>
          {rules.map(([id, n]) => (
            <option key={id} value={id}>{`${id} · ${titles.get(id) ?? ""} (${n})`}</option>
          ))}
        </select>
        <select aria-label="Provision" value={filters.provision} onChange={(e) => set({ provision: e.target.value })}>
          <option value="">All provisions</option>
          {provisions.map(([p, n]) => (
            <option key={p} value={p}>{`${p} (${n})`}</option>
          ))}
        </select>
        <select aria-label="Confidence" value={filters.confidence} onChange={(e) => set({ confidence: e.target.value as Filters["confidence"] })}>
          <option value="">Any confidence</option>
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>{`${c} confidence`}</option>
          ))}
        </select>
      </div>

      <div className="tablemeta" aria-live="polite">
        <span className="tabular">
          Showing {shown.length} of {findings.length} finding{findings.length === 1 ? "" : "s"}
        </span>
        {isFiltered(filters) && (
          <button type="button" className="textlink" onClick={() => onChange(EMPTY_FILTERS)}>
            Clear filters
          </button>
        )}
      </div>

      {shown.length === 0 ? (
        <p className="emptyrow">{findings.length === 0 ? "The scan reported no findings for the rules it checks." : "No findings match these filters."}</p>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Severity</th>
                <th scope="col" className="wide">
                  Location
                </th>
                <th scope="col" className="wide">
                  Provision
                </th>
                <th scope="col" className="wide">
                  Confidence
                </th>
                <th scope="col" className="wide">
                  Review
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.slice(0, limit).map((f) => (
                <tr
                  key={f.id}
                  onClick={(e) => {
                    if (!(e.target as HTMLElement).closest("a, button, select")) navigate(linkTo(f));
                  }}
                >
                  <td>
                    <Link to={linkTo(f)} className="rowtitle">
                      {f.title}
                    </Link>
                    <small className="mono">{f.rule_id}</small>
                    <small className="narrowonly mono">{describeLocation(f)}</small>
                  </td>
                  <td>
                    <SeverityBadge severity={f.severity} />
                    <span className="narrowonly">
                      <ConfidenceMeter confidence={f.confidence} />
                    </span>
                  </td>
                  <td className="wide mono location">{describeLocation(f)}</td>
                  <td className="wide">
                    <span className="chips">
                      {provisionsOf(f).map((p) => (
                        <span key={p} className="chip law">
                          {p}
                        </span>
                      ))}
                    </span>
                  </td>
                  <td className="wide">
                    <ConfidenceMeter confidence={f.confidence} />
                  </td>
                  <td className="wide review">{statusOf(f.id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.length > limit && (
            <div className="tablemore">
              <button type="button" className="textlink" onClick={() => setLimit(shown.length)}>
                Show all {shown.length} findings
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
