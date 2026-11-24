import { useState } from "react";
import { Link } from "react-router-dom";
import { Download, Printer, FileChartColumn } from "lucide-react";
import { report, rules, levels, countBy, provisions, locationOf } from "./data";
import { Heading, Select, useReviews } from "./ui";
function escape(value: string) {
  return value.replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ]!,
  );
}
function saveFile(content: string, type: string, extension: string) {
  const url = URL.createObjectURL(new Blob([content], { type })),
    a = document.createElement("a");
  a.href = url;
  a.download = report.id + "." + extension;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function Reports() {
  const { reviews } = useReviews(),
    c = report.coverage,
    counts = countBy(report.findings, "severity");
  function exportReport(format: string) {
    if (format === "JSON") {
      saveFile(
        JSON.stringify({ ...report, review_status: reviews }, null, 2),
        "application/json",
        "json",
      );
      return;
    }
    if (format === "HTML") {
      const rows = report.findings
        .map(
          (f) =>
            "<article><h2>" +
            escape(f.title) +
            "</h2><p>" +
            [
              f.rule_id,
              f.severity,
              "Confidence " + f.confidence,
              reviews[f.id],
              locationOf(f),
            ]
              .map(escape)
              .join(" · ") +
            "</p><pre>" +
            escape(f.evidence) +
            "</pre><p>" +
            escape(provisions(f)) +
            "</p><p>" +
            escape(f.severity_reason) +
            "</p><p>" +
            escape(f.fix) +
            "</p></article>",
        )
        .join("");
      saveFile(
        '<!doctype html><html lang="en"><meta charset="utf-8"><title>Sample audit report</title><style>body{max-width:52rem;margin:3rem auto;font:16px/1.55 system-ui}article{border-top:1px solid #aaa;break-inside:avoid}pre{white-space:pre-wrap}</style><h1>Sample audit · ' +
          report.repository +
          "</h1><p>" +
          report.disclaimer +
          "</p><p>" +
          c.analyzed +
          " files analyzed · " +
          c.executed.length +
          " rules executed</p><p>Manual review: " +
          c.manual.join(", ") +
          "</p>" +
          rows +
          "</html>",
        "text/html",
        "html",
      );
      return;
    }
    const results = report.findings.map((f) => ({
      ruleId: f.rule_id,
      level: ["critical", "high"].includes(f.severity) ? "error" : "warning",
      message: { text: f.title + " — " + f.evidence },
      ...(f.file
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.file },
                  ...(f.line ? { region: { startLine: f.line } } : {}),
                },
              },
            ],
          }
        : {}),
      properties: {
        confidence: f.confidence,
        severity: f.severity,
        reviewStatus: reviews[f.id],
      },
    }));
    saveFile(
      JSON.stringify(
        {
          version: "2.1.0",
          runs: [
            {
              tool: { driver: { name: "DPDP Auditor (sample report)" } },
              results,
            },
          ],
        },
        null,
        2,
      ),
      "application/json",
      "sarif",
    );
  }
  return (
    <section className="page reportpage">
      <Heading title="Reports" sub="Review and export the sample audit." />
      <div className="reporthead">
        <FileChartColumn size={38} />
        <div>
          <small>SAMPLE REPORT · {report.id}</small>
          <h2>{report.repository}</h2>
          <p>
            {report.findings.length} findings · {c.analyzed} files analyzed ·{" "}
            {c.executed.length} rules executed
          </p>
        </div>
      </div>
      <div className="detailgrid">
        <div className="panel">
          <h2 className="type-pixel">Findings by severity</h2>
          {levels.map((l) => (
            <div className="summaryrow" key={l}>
              <span>{l}</span>
              <div className="track">
                <i
                  style={{
                    width:
                      ((counts[l] || 0) / report.findings.length) * 100 + "%",
                  }}
                />
              </div>
              <b>{counts[l] || 0}</b>
            </div>
          ))}
          <h3>Mapped provisions</h3>
          <div className="chips">
            {Array.from(
              new Set(
                report.findings.flatMap((f) => [...f.law.act, ...f.law.rules]),
              ),
            ).map((v) => (
              <span key={v}>{v}</span>
            ))}
          </div>
        </div>
        <aside className="panel">
          <h2 className="type-pixel">Export report</h2>
          <p>Download this sample with its current review statuses.</p>
          <div className="exportgrid">
            {["JSON", "HTML", "SARIF"].map((f) => (
              <button
                className="btn secondary"
                key={f}
                onClick={() => exportReport(f)}
              >
                <Download size={16} />
                {f}
              </button>
            ))}
            <button className="btn secondary" onClick={() => window.print()}>
              <Printer size={16} />
              Print / PDF
            </button>
          </div>
          <small>{report.disclaimer}</small>
        </aside>
      </div>
      <div className="panel">
        <h2 className="type-pixel">Coverage and manual review</h2>
        <p>
          {c.analyzed} of {c.eligible} files analyzed. {c.excluded}.{" "}
          {c.skipped.length} planned rules skipped in this simulation.
        </p>
        {rules
          .filter((r) => r.status === "Manual review")
          .map((r) => (
            <div className="ruleline" key={r.id}>
              <code>{r.id}</code>
              <span>{r.title}</span>
            </div>
          ))}
        <Link className="textlink" to="/rules">
          View rule catalogue
        </Link>
      </div>
      <section className="printdetails">
        {report.findings.map((f) => (
          <article key={f.id}>
            <h2>{f.title}</h2>
            <p>
              {f.rule_id} · {f.severity} · {reviews[f.id]} · {locationOf(f)}
            </p>
            <pre>{f.evidence}</pre>
            <p>{provisions(f)}</p>
            <p>{f.fix}</p>
          </article>
        ))}
      </section>
    </section>
  );
}
export function Rules() {
  const [status, setStatus] = useState("All rules");
  return (
    <section className="page">
      <Heading
        title="Rule catalogue"
        sub="Project-plan rules and their coverage in this sample report."
      >
        <Select
          label="Filter rule coverage"
          value={status}
          items={["All rules", "Executed", "Skipped", "Manual review"]}
          change={setStatus}
        />
      </Heading>
      <div className="tablewrap">
        <table>
          <thead>
            <tr>
              <th className="type-pixel" scope="col">
                Rule
              </th>
              <th scope="col">Check</th>
              <th scope="col">Provision</th>
              <th className="type-pixel" scope="col">
                Demo coverage
              </th>
            </tr>
          </thead>
          <tbody>
            {rules
              .filter((r) => status === "All rules" || r.status === status)
              .map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.id}</td>
                  <td>
                    {r.title}
                    <small>{r.category}</small>
                  </td>
                  <td>{r.provision}</td>
                  <td>{r.status}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
