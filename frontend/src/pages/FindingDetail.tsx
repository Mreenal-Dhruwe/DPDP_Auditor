// One finding: masked code with the flagged line, what the detector saw, the scanner's
// severity and reason, detection confidence, the legal mapping, the fix, review status and
// exports. Rendered as a full page for direct links and inside the board's evidence drawer.
// Every scanner field is shown as reported; only the review status can change here.

import { ArrowLeft, ArrowRight, CircleCheck, FileCode2 } from "lucide-react";
import { Link, useLocation, useParams, useSearchParams } from "react-router";
import { CodeViewer } from "../components/CodeViewer";
import { ExportButtons } from "../components/ExportButtons";
import { LawCard } from "../components/LawCard";
import { ReviewSelect } from "../components/ReviewSelect";
import { ConfidenceMeter, Heading, Notice, SeverityBadge } from "../components/ui";
import { applyFilters, describeLocation, isFiltered, piiLabel, readFilters } from "../lib/findings";
import type { Finding } from "../types/contract";
import { useScan } from "./ScanLayout";

const CONFIDENCE_TEXT = {
  high: "The detector matched a clear pattern.",
  medium: "Likely, but the code may handle this elsewhere.",
  low: "A weak signal: verify it by hand before acting.",
} as const;
const SCOPE_TEXT = { line: "One place in the code", file: "A whole file", project: "Missing across the project" } as const;

export function FindingView({ finding, inDrawer = false }: { finding: Finding; inDrawer?: boolean }) {
  const { scanId, report } = useScan();
  const location = useLocation();
  const [params] = useSearchParams();
  const search = params.toString() ? `?${params}` : "";
  const filtered = applyFilters(report.findings, readFilters(params));
  const list = filtered.some((f) => f.id === finding.id) ? filtered : report.findings;
  const index = list.findIndex((f) => f.id === finding.id);
  const [prev, next] = [list[index - 1], list[index + 1]];
  const link = (f: Finding) => ({ pathname: `/scans/${scanId}/findings/${f.id}`, search });
  const navState = inDrawer ? location.state : undefined;

  return (
    <article className={`findingview${inDrawer ? " indrawer" : ""}`}>
      <div className="findingnav">
        {!inDrawer && (
          <Link className="textlink" to={`/scans/${scanId}${search}`}>
            <ArrowLeft aria-hidden="true" /> {report.target}: all findings
          </Link>
        )}
        <div className="stepper" aria-label="Findings">
          <span className="tabular">
            {index + 1} of {list.length}
            {list === filtered && isFiltered(readFilters(params)) ? " (filtered)" : ""}
          </span>
          {prev ? (
            <Link className="icon-btn" to={link(prev)} state={navState} replace={inDrawer} aria-label="Previous finding" title="Previous finding">
              <ArrowLeft aria-hidden="true" />
            </Link>
          ) : (
            <span className="icon-btn" aria-hidden="true" data-disabled>
              <ArrowLeft />
            </span>
          )}
          {next ? (
            <Link className="icon-btn" to={link(next)} state={navState} replace={inDrawer} aria-label="Next finding" title="Next finding">
              <ArrowRight aria-hidden="true" />
            </Link>
          ) : (
            <span className="icon-btn" aria-hidden="true" data-disabled>
              <ArrowRight />
            </span>
          )}
        </div>
      </div>

      <Heading
        eyebrow={
          <>
            <Link className="mono rulelink" to={`/rules?q=${finding.rule_id}#${finding.rule_id}`}>
              {finding.rule_id}
            </Link>{" "}
            · {finding.category}
          </>
        }
        title={finding.title}
      />
      <div className="findingmeta">
        <SeverityBadge severity={finding.severity} large />
        <ConfidenceMeter confidence={finding.confidence} />
        <span className="mono location">
          <FileCode2 aria-hidden="true" />
          {describeLocation(finding)}
        </span>
      </div>

      <div className="detailgrid">
        <div className="maincol">
          <section className="panel">
            <div className="between">
              <h2 className="type-pixel">Evidence</h2>
              <span className="chip">{SCOPE_TEXT[finding.scope]}</span>
            </div>
            <CodeViewer finding={finding} />
            <h3>What the detector saw</h3>
            <p className="evidence mono">{finding.evidence}</p>
            <small className="note">Saved at scan time with secrets and personal data masked. The uploaded code itself was deleted.</small>
            {finding.pii.length > 0 && (
              <>
                <h3>Personal data involved</h3>
                <ul className="chips">
                  {finding.pii.map((p) => (
                    <li key={p} className="chip pii">
                      {piiLabel(p)}
                    </li>
                  ))}
                </ul>
              </>
            )}
          </section>
          <section className="panel">
            <h2 className="type-pixel">Recommended fix</h2>
            <div className="fix">
              <CircleCheck aria-hidden="true" />
              <p>{finding.fix}</p>
            </div>
          </section>
        </div>

        <aside className="sidecol">
          <section className="panel properties">
            <h2 className="type-pixel">Finding properties</h2>
            <dl>
              <div>
                <dt>Severity</dt>
                <dd>
                  <SeverityBadge severity={finding.severity} />
                  <p>{finding.severity_reason}</p>
                </dd>
              </div>
              <div>
                <dt>Detection confidence</dt>
                <dd>
                  <ConfidenceMeter confidence={finding.confidence} />
                  <p>{CONFIDENCE_TEXT[finding.confidence]}</p>
                </dd>
              </div>
              <div>
                <dt>Review status</dt>
                <dd>
                  <ReviewSelect id={finding.id} title={finding.title} />
                  <p>Saved in this browser only.</p>
                </dd>
              </div>
            </dl>
          </section>
          <LawCard law={finding.law} penalty={finding.penalty} disclaimer={report.disclaimer} />
          <section className="panel">
            <h2 className="type-pixel">Export the report</h2>
            <ExportButtons scanId={scanId} target={report.target} />
            <small className="note">Every format holds all {report.summary.total} findings.</small>
          </section>
        </aside>
      </div>
    </article>
  );
}

/** Direct link to a finding: a full page. */
export function FindingDetailPage() {
  const { findingId = "" } = useParams();
  const { scanId, report } = useScan();
  const finding = report.findings.find((f) => f.id === findingId);
  if (!finding) {
    return (
      <section className="page narrow arrive">
        <Heading eyebrow="Finding" title="Finding not found" />
        <Notice kind="error" title="Unknown finding">
          This report has no finding with id {findingId}.
        </Notice>
        <div className="formactions">
          <Link className="btn mint" to={`/scans/${scanId}`}>
            Back to the overview
          </Link>
        </div>
      </section>
    );
  }
  return (
    <section className="page arrive">
      <FindingView finding={finding} />
    </section>
  );
}
