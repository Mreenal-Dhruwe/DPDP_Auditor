// Report (/scans/:id/report): summary, severity distribution, mapped provisions, coverage,
// review progress and downloads. Exports are the server's (authoritative, masked); the
// review notes (cleared when you reload or leave) are offered as a separate, clearly labelled file.

import { ClipboardList, FileChartColumn } from "lucide-react";
import { Link } from "react-router";
import { ExportButtons } from "../components/ExportButtons";
import { Heading } from "../components/ui";
import { compareProvisions, countBy, formatDate, SEVERITY_LABEL } from "../lib/findings";
import { STATUSES, useReviews } from "../lib/reviews";
import { SEVERITIES } from "../types/contract";
import { scanBase } from "../lib/paths";
import { useScan } from "./ScanLayout";

export function ReportPage() {
  const { scanId, report } = useScan();
  const { counts, all } = useReviews();
  const total = report.summary.total;
  const coverage = report.coverage;
  const provisions = Object.entries(report.summary.by_provision).sort((a, b) => compareProvisions(a[0], b[0]));
  const toVerify = report.findings.filter((f) => f.confidence === "low");

  const downloadReviews = () => {
    const findings = Object.fromEntries(
      report.findings.map((f) => [f.id, { rule_id: f.rule_id, title: f.title, status: all[f.id]?.status ?? "Open", changed_at: all[f.id]?.at || null }]),
    );
    const body = {
      note: "Review notes kept in one browser. Not part of the scanner's report; scanner fields are unchanged.",
      scan_id: scanId,
      target: report.target,
      exported_at: new Date().toISOString(),
      findings,
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(body, null, 2)], { type: "application/json" }));
    const link = Object.assign(document.createElement("a"), { href: url, download: `dpdp-review-${report.target}.json` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <section className="page arrive reportpage">
      <Heading eyebrow="Report" title="Compliance report" sub="Everything the scan found, mapped to the DPDP Act and Rules, ready to download." />

      <div className="reporthead">
        <FileChartColumn size={38} aria-hidden="true" />
        <div>
          <span className="fieldlabel">REPORT · SCAN {scanId.slice(0, 8).toUpperCase()}</span>
          <h2 className="breakall">{report.target}</h2>
          <p className="tabular">
            {total} findings · {report.files_scanned} files read · {coverage?.rules_checked.length ?? 0} rules checked · {formatDate(report.generated_at)}
          </p>
        </div>
      </div>

      <div className="detailgrid">
        <div className="maincol">
          <section className="panel">
            <h2 className="type-pixel">Findings by severity</h2>
            {SEVERITIES.map((s) => (
              <div className={`summaryrow sev-${s}`} key={s}>
                <span className="sevname">
                  <i aria-hidden="true" />
                  {SEVERITY_LABEL[s]}
                </span>
                <div className="track" aria-hidden="true">
                  <i style={{ transform: `scaleX(${total ? report.summary.by_severity[s] / total : 0})` }} />
                </div>
                <b className="tabular">{report.summary.by_severity[s]}</b>
              </div>
            ))}
            <h3>Mapped provisions</h3>
            <ul className="chips">
              {provisions.map(([p, n]) => (
                <li key={p} className="chip law">
                  {p} <b className="tabular">{n}</b>
                </li>
              ))}
            </ul>
            <h3>Categories</h3>
            <ul className="chips">
              {countBy(report.findings, (f) => f.category).map(([c, n]) => (
                <li key={c} className="chip">
                  {c} <b className="tabular">{n}</b>
                </li>
              ))}
            </ul>
          </section>

          <section className="panel">
            <h2 className="type-pixel">Coverage and manual checks</h2>
            <p className="muted">
              {report.files_scanned} files read, never executed. {coverage?.rules_checked.length ?? 0} of{" "}
              {(coverage?.rules_checked.length ?? 0) + (coverage?.rules_not_checked.length ?? 0)} rules have an automated check.
            </p>
            {coverage && coverage.rules_not_checked.length > 0 && (
              <>
                <h3>Rules that need a manual review</h3>
                {coverage.rules_not_checked.map((id) => (
                  <div className="ruleline" key={id}>
                    <code>{id}</code>
                  </div>
                ))}
              </>
            )}
            <h3>Low-confidence findings to verify by hand</h3>
            {toVerify.length ? (
              toVerify.map((f) => (
                <div className="ruleline" key={f.id}>
                  <code>{f.rule_id}</code>
                  <Link className="textlink" to={`${scanBase(scanId)}/findings/${f.id}`}>
                    {f.title}
                  </Link>
                </div>
              ))
            ) : (
              <p className="muted">None: every finding has medium or high confidence.</p>
            )}
            <Link className="textlink spaced" to="/rules">
              View the rule catalogue
            </Link>
          </section>
        </div>

        <aside className="sidecol">
          <section className="panel">
            <h2 className="type-pixel">Download</h2>
            <p className="muted">Generated by the server for this scan, with evidence masked.</p>
            <ExportButtons scanId={scanId} target={report.target} />
            <small className="note">{report.disclaimer}</small>
          </section>
          <section className="panel">
            <h2 className="type-pixel">Review progress</h2>
            {STATUSES.map((s) => (
              <div className="summaryrow" key={s}>
                <span>{s}</span>
                <div className="track" aria-hidden="true">
                  <i style={{ transform: `scaleX(${total ? counts[s] / total : 0})` }} />
                </div>
                <b className="tabular">{counts[s]}</b>
              </div>
            ))}
            <button type="button" className="btn ghost small" onClick={downloadReviews}>
              <ClipboardList aria-hidden="true" />
              Review notes (JSON)
            </button>
            <small className="note">Cleared when you reload or leave; download them to keep them. Not part of the scanner's report.</small>
          </section>
        </aside>
      </div>
    </section>
  );
}
