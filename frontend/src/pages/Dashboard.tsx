// Screen 2: the results dashboard for one scan.

import { Link, useParams, useSearchParams } from "react-router";
import { SAMPLE_ID } from "../api";
import { CoverageBox } from "../components/CoverageBox";
import { ExportButtons } from "../components/ExportButtons";
import { FindingsTable } from "../components/FindingsTable";
import { ProvisionChart } from "../components/ProvisionChart";
import { StatTiles } from "../components/StatTiles";
import { Card, ErrorBox, Loading } from "../components/States";
import { formatDate, readFilters, writeFilters, type Filters } from "../lib/findings";
import { useReport } from "../lib/useReport";
import type { Finding, Severity } from "../types/contract";

export function Dashboard() {
  const { scanId = "" } = useParams();
  const { report, error } = useReport(scanId);
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);

  if (error) return <ReportError scanId={scanId} status={error.status} message={error.message} />;
  if (!report) return <Loading label="Loading the report…" />;

  const setFilters = (next: Filters) => setParams(writeFilters(next), { replace: true });
  const toggleSeverity = (s: Severity) =>
    setFilters({ ...filters, severities: filters.severities.includes(s) ? filters.severities.filter((x) => x !== s) : [...filters.severities, s] });
  const search = params.toString();
  const linkTo = (f: Finding) => `/scans/${scanId}/findings/${f.id}${search ? `?${search}` : ""}`;

  return (
    <div className="space-y-6">
      {scanId === SAMPLE_ID && (
        <p className="rounded-lg border border-line bg-accent-soft px-4 py-2.5 text-sm text-ink-2">
          Sample report: what the scanner reports for our deliberately vulnerable target_app, with three illustrative
          findings added so every severity appears. <Link to="/" className="font-medium text-accent hover:underline">Run your own scan</Link>
        </p>
      )}

      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <p className="text-sm text-muted">Compliance report</p>
          <h1 className="mt-0.5 break-all text-2xl font-semibold tracking-tight sm:text-3xl">{report.target}</h1>
          <p className="tabular mt-1 text-sm text-ink-2">
            {report.summary.total} finding{report.summary.total === 1 ? "" : "s"} · {report.files_scanned} files ·{" "}
            {formatDate(report.generated_at)} · rules v{report.rules_version}
          </p>
        </div>
        <ExportButtons scanId={scanId} target={report.target} />
      </div>

      <StatTiles summary={report.summary} selected={filters.severities} onToggle={toggleSeverity} />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_340px]">
        <Card title="Findings by DPDP provision">
          <ProvisionChart
            findings={report.findings}
            selected={filters.provision}
            onSelect={(provision) => setFilters({ ...filters, provision })}
          />
        </Card>
        <Card title="Scan coverage">
          <CoverageBox coverage={report.coverage} filesScanned={report.files_scanned} />
        </Card>
      </div>

      <section className="rounded-xl border border-line bg-surface" aria-labelledby="findings-heading">
        <h2 id="findings-heading" className="px-4 pt-4 text-sm font-semibold sm:px-5">
          Findings
        </h2>
        <FindingsTable findings={report.findings} filters={filters} onChange={setFilters} linkTo={linkTo} />
      </section>

      <p className="text-xs text-muted">{report.disclaimer}</p>
    </div>
  );
}

export function ReportError({ scanId, status, message }: { scanId: string; status: number; message: string }) {
  if (status === 409) {
    return (
      <div className="mx-auto max-w-xl py-8">
        <ErrorBox title="This scan has not finished">{message}</ErrorBox>
        <Link to={`/scans/${scanId}/progress`} className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
          Follow its progress
        </Link>
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-xl py-8">
      <ErrorBox title={status === 404 ? "Report not found" : "Could not load the report"}>{message}</ErrorBox>
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
        Start a new scan
      </Link>
    </div>
  );
}
