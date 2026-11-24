// Overview (/scans/:id): the dashboard. Dark top band (finding breakdown by severity and
// detection confidence, findings per provision, scan summary), light band (coverage,
// personal data exposed, review queue) and the filterable findings table. Every number
// comes from the selected report; filters live in the URL.

import { ArrowRight, FileCode2, Layers3, ListChecks, ShieldAlert } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { FindingsTable } from "../components/FindingsTable";
import { ProvisionChart } from "../components/ProvisionChart";
import { Heading, Notice } from "../components/ui";
import { applyFilters, countBy, formatDate, piiLabel, readFilters, SEVERITY_LABEL, writeFilters, type Filters } from "../lib/findings";
import { STATUSES, useReviews } from "../lib/reviews";
import { isSample } from "../lib/scope";
import { expiryOf } from "../lib/session";
import type { Finding, Severity } from "../types/contract";
import { SEVERITIES } from "../types/contract";
import { useScan } from "./ScanLayout";

const KIND_LABEL: Record<string, string> = {
  python: "Python",
  javascript: "JavaScript",
  typescript: "TypeScript",
  templates: "Templates",
  sql: "SQL",
  config: "Config",
  other: "Other",
};

export function Overview() {
  const { scanId, report } = useScan();
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);
  const setFilters = (next: Filters) => setParams(writeFilters(next), { replace: true });
  const search = params.toString();
  const linkTo = (f: Finding) => `/scans/${scanId}/findings/${f.id}${search ? `?${search}` : ""}`;

  // The top of the page follows the category only; the table follows every filter.
  const inCategory = filters.category ? report.findings.filter((f) => f.category === filters.category) : report.findings;
  const inView = applyFilters(report.findings, filters);
  const categories = countBy(report.findings, (f) => f.category);
  const toggleSeverity = (s: Severity) =>
    setFilters({ ...filters, severities: filters.severities.includes(s) ? filters.severities.filter((x) => x !== s) : [...filters.severities, s] });

  return (
    <section className="dashboard arrive">
      <div className="page topdash">
        {isSample(scanId) && (
          <div className="samplenote">
            <Notice title="Saved sample, not a live scan">
              {scanId === "sample" ? (
                <>
                  What the scanner reports for our deliberately vulnerable target_app, plus three illustrative findings so every
                  severity appears. It ships with the app and is never deleted.
                </>
              ) : (
                <>Report saved earlier by the scanner command line on {report.target}. It is never deleted and does not expire.</>
              )}{" "}
              <Link className="textlink" to="/scan">Run your own scan</Link>
            </Notice>
          </div>
        )}
        <Heading
          eyebrow="Audit overview"
          title={<span className="breakall">{report.target}</span>}
          sub={
            <span className="tabular">
              {report.summary.total} findings · {report.files_scanned} files · {formatDate(report.generated_at)} · rules v{report.rules_version}
              {!isSample(scanId) && (
                <>
                  <br />
                  <ExpiryNote scanId={scanId} />
                </>
              )}
            </span>
          }
        >
          <select aria-label="Filter the overview by category" value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
            <option value="">All categories</option>
            {categories.map(([c, n]) => (
              <option key={c} value={c}>{`${c} (${n})`}</option>
            ))}
          </select>
        </Heading>

        <div className="dashgrid">
          <div>
            <h2 className="type-pixel">Finding breakdown</h2>
            <Breakdown findings={inCategory} selected={filters.severities} onToggle={toggleSeverity} />
            <ProvisionChart findings={inCategory} selected={filters.provision} onSelect={(provision) => setFilters({ ...filters, provision })} />
          </div>
          <div>
            <h2 className="type-pixel">Scan summary</h2>
            <div className="metrics">
              {(
                [
                  [Layers3, inView.length, "Findings in view", `of ${report.summary.total} in the scan`],
                  [ShieldAlert, inView.filter((f) => f.severity === "critical").length, "Critical in view", "top penalty band"],
                  [FileCode2, report.files_scanned, "Files read · scan", "never executed"],
                  [ListChecks, report.coverage?.rules_checked.length ?? 0, "Rules checked · scan", `of ${(report.coverage?.rules_checked.length ?? 0) + (report.coverage?.rules_not_checked.length ?? 0)} in the catalogue`],
                ] as const
              ).map(([Icon, value, label, note]) => (
                <div key={label}>
                  <Icon size={19} aria-hidden="true" />
                  <strong className="tabular">{value}</strong>
                  <span>{label}</span>
                  <small>{note}</small>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <LightBand scanId={scanId} findings={inCategory} />

      <div className="page">
        <div className="between sectionhead">
          <h2>Findings in scope</h2>
          <div className="formactions tight">
            <Link className="textlink" to={`/scans/${scanId}/findings`}>
              Open the review board
            </Link>
            <Link className="textlink" to={`/scans/${scanId}/report`}>
              Report and exports
            </Link>
          </div>
        </div>
        <FindingsTable findings={report.findings} filters={filters} onChange={setFilters} linkTo={linkTo} />
        <p className="footnote">{report.disclaimer}</p>
      </div>
    </section>
  );
}

function ExpiryNote({ scanId }: { scanId: string }) {
  const at = expiryOf(scanId);
  const time = at ? new Date(at).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) : null;
  return (
    <small className="expiry">
      This scan is deleted from the server {time ? `at ${time}` : "30 minutes after it was created"}, or when you reload or leave.
    </small>
  );
}

/** Severity rows split by detection confidence: confirmed (high) right, to confirm left.
 *  Each row is a severity filter for the table. */
function Breakdown({ findings, selected, onToggle }: { findings: Finding[]; selected: Severity[]; onToggle: (s: Severity) => void }) {
  const rows = SEVERITIES.map((s) => ({
    severity: s,
    high: findings.filter((f) => f.severity === s && f.confidence === "high").length,
    review: findings.filter((f) => f.severity === s && f.confidence !== "high").length,
  }));
  const max = Math.max(1, ...rows.flatMap((r) => [r.high, r.review]));
  return (
    <div className="breakdown">
      <div className="legend" aria-hidden="true">
        <span className="tocheck">
          <i />
          Needs confirmation (medium or low confidence)
        </span>
        <span className="sure">
          <i />
          High confidence
        </span>
      </div>
      <div role="group" aria-label="Filter by severity">
        {rows.map((r) => (
          <button
            key={r.severity}
            type="button"
            className={`compare sev-${r.severity}`}
            aria-pressed={selected.includes(r.severity)}
            aria-label={`${SEVERITY_LABEL[r.severity]}: ${r.high + r.review} findings, ${r.high} high confidence, ${r.review} to confirm`}
            onClick={() => onToggle(r.severity)}
          >
            <span className="sevname">
              <i aria-hidden="true" />
              {SEVERITY_LABEL[r.severity]}
            </span>
            <span className="halves" aria-hidden="true">
              <span>
                <b className="tabular">{r.review}</b>
                <i style={{ width: `${(r.review / max) * 72}%` }} />
              </span>
              <span>
                <i style={{ width: `${(r.high / max) * 72}%` }} />
                <b className="tabular">{r.high}</b>
              </span>
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}

function LightBand({ scanId, findings }: { scanId: string; findings: Finding[] }) {
  const { report } = useScan();
  const { statusOf } = useReviews();
  const coverage = report.coverage;
  const checked = coverage?.rules_checked.length ?? 0;
  const total = checked + (coverage?.rules_not_checked.length ?? 0);
  const pii = countBy(findings, (f) => f.pii).slice(0, 8);
  const files = new Set(findings.filter((f) => f.pii.length && f.file).map((f) => f.file)).size;
  const toConfirm = findings.filter((f) => f.confidence !== "high").length;
  const resolved = findings.filter((f) => statusOf(f.id) === STATUSES[3]).length;

  return (
    <div className="lightband">
      <section>
        <h2 className="type-pixel">Scan coverage</h2>
        <strong className="tabular">
          {checked}
          <span>/{total}</span>
        </strong>
        <p>rules checked automatically</p>
        <div className="track">
          <i style={{ transform: `scaleX(${total ? checked / total : 0})` }} />
        </div>
        <div className="chips">
          {Object.entries(coverage?.files_by_kind ?? {})
            .sort((a, b) => b[1] - a[1])
            .map(([kind, n]) => (
              <span key={kind}>
                {KIND_LABEL[kind] ?? kind} <b className="tabular">{n}</b>
              </span>
            ))}
        </div>
        <small>No finding for a checked rule means its detector saw no sign of the problem, not that the code is compliant.</small>
      </section>
      <section>
        <h2 className="type-pixel">Personal data exposed</h2>
        <strong className="tabular">{pii.length}</strong>
        <p>
          kinds of personal data in {files} file{files === 1 ? "" : "s"}
        </p>
        {pii.length ? (
          <div className="chips">
            {pii.map(([label, n]) => (
              <span key={label}>
                {piiLabel(label)} <b className="tabular">{n}</b>
              </span>
            ))}
          </div>
        ) : (
          <small>No finding in view names a personal-data field.</small>
        )}
      </section>
      <section>
        <h2 className="type-pixel">Review queue</h2>
        <strong className="tabular">{toConfirm}</strong>
        <p>findings to confirm against the project (medium or low confidence)</p>
        <div className="track">
          <i style={{ transform: `scaleX(${findings.length ? resolved / findings.length : 0})` }} />
        </div>
        <small className="tabular">
          {resolved} of {findings.length} marked resolved (cleared when you reload or leave)
        </small>
        <Link className="bandlink" to={`/scans/${scanId}/findings`}>
          Open the review board <ArrowRight aria-hidden="true" />
        </Link>
      </section>
    </div>
  );
}
