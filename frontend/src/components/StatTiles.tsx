import { SEVERITY_LABEL } from "../lib/findings";
import type { Severity, Summary } from "../types/contract";
import { SEVERITIES } from "../types/contract";
import { SEVERITY_DOT } from "./SeverityBadge";

const HINT: Record<Severity, string> = {
  critical: "Exploitable now, top penalty band",
  high: "Serious gap, fix before release",
  medium: "Gap with limited exposure",
  low: "Hardening, defence in depth",
  info: "For awareness, usually allowed",
};

/** One tile per severity. A tile is also a filter toggle for the findings table. */
export function StatTiles({ summary, selected, onToggle }: { summary: Summary; selected: Severity[]; onToggle: (s: Severity) => void }) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      {SEVERITIES.map((severity) => {
        const count = summary.by_severity[severity];
        const active = selected.includes(severity);
        return (
          <button
            key={severity}
            type="button"
            aria-pressed={active}
            onClick={() => onToggle(severity)}
            title={active ? "Click to stop filtering by this severity" : "Click to show only this severity"}
            className={`group relative overflow-hidden rounded-xl border bg-surface px-4 pb-3 pt-4 text-left transition-colors ${
              active ? "border-accent ring-1 ring-accent" : "border-line hover:border-line-strong"
            } ${count === 0 ? "opacity-70" : ""}`}
          >
            <span className={`absolute inset-x-0 top-0 h-1 ${SEVERITY_DOT[severity]}`} aria-hidden="true" />
            <span className="flex items-center gap-1.5 text-sm font-medium text-ink-2">
              <span className={`size-2 rounded-full ${SEVERITY_DOT[severity]}`} aria-hidden="true" />
              {SEVERITY_LABEL[severity]}
            </span>
            <span className="mt-1 block text-3xl font-semibold tracking-tight text-ink">{count}</span>
            <span className="mt-0.5 block text-xs text-muted">{HINT[severity]}</span>
          </button>
        );
      })}
    </div>
  );
}
