// Screen 3: one finding, with its code, the law behind it, severity and the fix.

import { Link, useParams, useSearchParams } from "react-router";
import { CodeViewer } from "../components/CodeViewer";
import { ExportButtons } from "../components/ExportButtons";
import { LawCard } from "../components/LawCard";
import { ReportError } from "../components/ReportError";
import { ConfidenceTag, SeverityBadge } from "../components/SeverityBadge";
import { Card, ErrorBox, Loading } from "../components/States";
import { applyFilters, describeLocation, isFiltered, readFilters } from "../lib/findings";
import { useReport } from "../lib/useReport";

const CONFIDENCE_TEXT = {
  high: "The detector matched a clear pattern.",
  medium: "Likely, but the code may handle this elsewhere.",
  low: "A weak signal: check it by hand before acting.",
} as const;

export function FindingDetail() {
  const { scanId = "", findingId = "" } = useParams();
  const [params] = useSearchParams();
  const { report, error } = useReport(scanId);

  if (error) return <ReportError scanId={scanId} status={error.status} message={error.message} />;
  if (!report) return <Loading label="Loading the finding…" />;

  const search = params.toString() ? `?${params}` : "";
  const back = `/scans/${scanId}${search}`;
  const finding = report.findings.find((f) => f.id === findingId);
  if (!finding) {
    return (
      <div className="mx-auto max-w-xl py-8">
        <ErrorBox title="Finding not found">This report has no finding with id {findingId}.</ErrorBox>
        <Link to={back} className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
          Back to all findings
        </Link>
      </div>
    );
  }

  // Previous / next follow the dashboard's filters; if this finding is filtered out, use all.
  const filtered = applyFilters(report.findings, readFilters(params));
  const list = filtered.some((f) => f.id === finding.id) ? filtered : report.findings;
  const index = list.findIndex((f) => f.id === finding.id);
  const prev = list[index - 1];
  const next = list[index + 1];
  const link = (id: string) => `/scans/${scanId}/findings/${id}${search}`;

  return (
    <div className="space-y-6">
      <nav className="flex flex-wrap items-center justify-between gap-3 text-sm" aria-label="Findings">
        <Link to={back} className="font-medium text-accent hover:underline">
          ← {report.target}: all findings
        </Link>
        <div className="flex items-center gap-2">
          <span className="tabular text-xs text-muted">
            {index + 1} of {list.length}
            {list === filtered && isFiltered(readFilters(params)) ? " (filtered)" : ""}
          </span>
          <NavButton to={prev && link(prev.id)} label="Previous finding">←</NavButton>
          <NavButton to={next && link(next.id)} label="Next finding">→</NavButton>
        </div>
      </nav>

      <header>
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} size="lg" />
          <span className="font-mono text-sm text-ink-2">{finding.rule_id}</span>
          <span className="text-sm text-muted">· {finding.category}</span>
        </div>
        <h1 className="mt-3 text-2xl font-semibold tracking-tight sm:text-3xl">{finding.title}</h1>
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
          <span className="break-all font-mono text-ink-2">{describeLocation(finding)}</span>
          <ConfidenceTag confidence={finding.confidence} />
          {finding.pii.length > 0 && (
            <span className="flex flex-wrap items-center gap-1">
              <span className="text-xs text-muted">Personal data:</span>
              {finding.pii.map((p) => (
                <span key={p} className="rounded bg-accent-soft px-1.5 py-0.5 text-xs font-medium text-accent">
                  {p.replaceAll("_", " ")}
                </span>
              ))}
            </span>
          )}
        </div>
      </header>

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_360px]">
        <div className="min-w-0 space-y-6">
          <Card title="Code">
            <CodeViewer finding={finding} />
          </Card>
          <Card title="Evidence">
            <p className="break-words font-mono text-[13px] leading-relaxed text-ink">{finding.evidence}</p>
            <p className="mt-2 text-xs text-muted">What the detector saw, on one line, with secrets and personal data masked.</p>
          </Card>
          <Card title="Recommended fix">
            <div className="flex gap-3">
              <svg viewBox="0 0 20 20" className="mt-0.5 size-5 shrink-0 text-ok-ink" aria-hidden="true">
                <circle cx="10" cy="10" r="9" fill="currentColor" opacity=".14" />
                <path d="M6 10.5l2.7 2.7L14 7.8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
              <p className="leading-relaxed text-ink">{finding.fix}</p>
            </div>
          </Card>
        </div>

        <div className="min-w-0 space-y-6">
          <Card title="Severity">
            <div className="space-y-3 text-sm">
              <SeverityBadge severity={finding.severity} />
              <p className="leading-relaxed text-ink">{finding.severity_reason}</p>
              <p className="border-t border-line pt-3 text-xs text-ink-2">
                <span className="font-medium text-ink">Confidence {finding.confidence}.</span> {CONFIDENCE_TEXT[finding.confidence]}
              </p>
            </div>
          </Card>
          <Card title="Law">
            <LawCard law={finding.law} penalty={finding.penalty} />
          </Card>
          <Card title="Export the report">
            <ExportButtons scanId={scanId} target={report.target} align="start" />
            <p className="mt-2 text-xs text-muted">Every format holds all {report.summary.total} findings.</p>
          </Card>
        </div>
      </div>

      <p className="text-xs text-muted">{report.disclaimer}</p>
    </div>
  );
}

function NavButton({ to, label, children }: { to?: string; label: string; children: string }) {
  const style = "inline-flex size-8 items-center justify-center rounded-md border border-line-strong bg-surface text-ink";
  return to ? (
    <Link to={to} aria-label={label} title={label} className={`${style} hover:border-accent hover:text-accent`}>
      {children}
    </Link>
  ) : (
    <span aria-hidden="true" className={`${style} opacity-40`}>
      {children}
    </span>
  );
}
