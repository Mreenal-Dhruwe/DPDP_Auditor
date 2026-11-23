// The masked source lines saved in the report (uploads are deleted after the scan), with
// the flagged line marked. Rendered as text only: never as HTML.

import type { Finding } from "../types/contract";

export function CodeViewer({ finding }: { finding: Finding }) {
  const { context, file, line, scope } = finding;
  if (!context || line === null) {
    return (
      <div className="code empty">
        <p>
          {scope === "file"
            ? `This finding is about the whole of ${file}, so there is no single line to show.`
            : scope === "project"
              ? "This finding is about something missing from the project as a whole, so there is no line to show."
              : "The code around this line could not be read."}
        </p>
        <pre>{finding.evidence}</pre>
      </div>
    );
  }
  const last = context.start_line + context.lines.length - 1;
  const width = String(last).length;
  return (
    <figure className="codefig">
      <figcaption>
        <span className="mono breakall">{file}</span>
        <span className="tabular">
          lines {context.start_line}–{last}
        </span>
      </figcaption>
      {/* relative: keeps the screen-reader text inside the scroll box */}
      <div className="code" style={{ position: "relative" }}>
        {context.lines.map((text, i) => {
          const number = context.start_line + i;
          const hit = number === line;
          return (
            <div key={number} className={hit ? "flagged" : undefined} aria-current={hit ? "true" : undefined}>
              <span aria-hidden="true" style={{ minWidth: `${width + 1}ch` }}>
                {number}
              </span>
              <code>
                {text || " "}
                {hit && <span className="sr-only"> (flagged line {number})</span>}
              </code>
            </div>
          );
        })}
      </div>
    </figure>
  );
}
