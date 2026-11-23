import type { Finding, Severity } from "../types/contract";

const HIT_BORDER: Record<Severity, string> = {
  critical: "border-sev-critical",
  high: "border-sev-high",
  medium: "border-sev-medium",
  low: "border-sev-low",
  info: "border-sev-info",
};

/** The masked source lines saved in the report (uploads are deleted after the scan),
 *  with the flagged line highlighted. No syntax colouring: the flagged line is the point. */
export function CodeViewer({ finding }: { finding: Finding }) {
  const { context, file, line, scope, severity } = finding;
  if (!context || line === null) {
    return (
      <p className="rounded-lg bg-surface-2 px-4 py-6 text-center text-sm text-ink-2">
        {scope === "file"
          ? `This finding is about the whole of ${file}, so there is no single line to show.`
          : scope === "project"
            ? "This finding is about something missing from the project as a whole, so there is no line to show."
            : "The code around this line could not be read."}
      </p>
    );
  }
  const last = context.start_line + context.lines.length - 1;
  const width = String(last).length;
  return (
    <figure>
      <figcaption className="mb-2 flex flex-wrap items-baseline justify-between gap-2 text-xs text-muted">
        <span className="break-all font-mono text-ink-2">{file}</span>
        <span className="tabular">
          lines {context.start_line}–{last}
        </span>
      </figcaption>
      <div className="overflow-x-auto rounded-lg border border-line bg-code-bg">
        <pre className="min-w-full py-2 font-mono text-[13px] leading-6">
          {context.lines.map((text, i) => {
            const number = context.start_line + i;
            const hit = number === line;
            return (
              <div
                key={number}
                className={`flex border-l-[3px] pr-4 ${hit ? `${HIT_BORDER[severity]} bg-code-hit` : "border-transparent"}`}
                aria-current={hit ? "true" : undefined}
              >
                <span
                  className={`tabular select-none px-3 text-right ${hit ? "font-semibold text-ink" : "text-muted"}`}
                  style={{ minWidth: `${width + 2}ch` }}
                  aria-hidden="true"
                >
                  {number}
                </span>
                <code className={hit ? "text-ink" : "text-ink-2"}>
                  {text || " "}
                  {hit && <span className="sr-only"> (flagged line {number})</span>}
                </code>
              </div>
            );
          })}
        </pre>
      </div>
      <p className="mt-2 text-xs text-muted">
        Excerpt saved at scan time with secrets and personal data masked. The uploaded code itself was deleted.
      </p>
    </figure>
  );
}
