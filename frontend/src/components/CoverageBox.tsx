// What the scan looked at, so "no findings" is never read as "compliant".

import { useEffect, useState } from "react";
import { getRuleTitles } from "../api";
import type { Coverage } from "../types/contract";

const KIND_LABEL: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
  templates: "Templates",
  sql: "SQL",
  config: "Config",
  other: "Other",
};

export function CoverageBox({ coverage, filesScanned }: { coverage: Coverage | null; filesScanned: number }) {
  const [titles, setTitles] = useState<Record<string, string>>({});
  useEffect(() => {
    let live = true;
    getRuleTitles().then((t) => live && setTitles(t));
    return () => {
      live = false;
    };
  }, []);

  if (!coverage) {
    return <p className="text-sm text-muted">This report has no coverage data. {filesScanned} files were scanned.</p>;
  }
  const checked = coverage.rules_checked.length;
  const total = checked + coverage.rules_not_checked.length;
  const kinds = Object.entries(coverage.files_by_kind).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className="text-ink">
          <span className="text-2xl font-semibold tracking-tight">{checked}</span>
          <span className="text-ink-2"> of {total} rules checked automatically</span>
        </p>
        <div className="mt-2 flex h-2 gap-0.5 overflow-hidden rounded-full" aria-hidden="true">
          <span className="rounded-l-full" style={{ width: `${(checked / Math.max(total, 1)) * 100}%`, background: "var(--series-1)" }} />
          <span className="flex-1 rounded-r-full bg-line" />
        </div>
        <p className="mt-2 text-xs text-muted">
          No finding for a checked rule means its detector found nothing, not that the code is compliant.
        </p>
      </div>

      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Files scanned · {filesScanned}</h3>
        <ul className="mt-1.5 flex flex-wrap gap-1.5">
          {kinds.map(([kind, n]) => (
            <li key={kind} className="rounded-md bg-surface-2 px-2 py-0.5 text-xs text-ink-2">
              {KIND_LABEL[kind] ?? kind} <span className="tabular font-medium text-ink">{n}</span>
            </li>
          ))}
        </ul>
      </div>

      {coverage.rules_not_checked.length > 0 && (
        <details className="group">
          <summary className="cursor-pointer list-none text-xs font-semibold uppercase tracking-wide text-muted hover:text-ink">
            <span className="mr-1 inline-block transition-transform group-open:rotate-90" aria-hidden="true">›</span>
            Needs manual review · {coverage.rules_not_checked.length} rules
          </summary>
          <ul className="mt-2 space-y-1">
            {coverage.rules_not_checked.map((id) => (
              <li key={id} className="text-xs text-ink-2">
                <span className="font-mono text-ink">{id}</span>
                {titles[id] && <span> · {titles[id]}</span>}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
