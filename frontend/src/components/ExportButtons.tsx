import { useState } from "react";
import { ApiError, canExport, downloadReport, EXPORT_FORMATS, type ExportFormat } from "../api";

const LABEL: Record<ExportFormat, string> = { html: "HTML", pdf: "PDF", sarif: "SARIF", json: "JSON" };
const HINT: Record<ExportFormat, string> = {
  html: "Self-contained report to open in a browser or share",
  pdf: "Printable report (needs WeasyPrint's Pango libraries on the server)",
  sarif: "SARIF 2.1.0 for GitHub code scanning and IDEs",
  json: "The master report.json",
};

/** Download buttons for the whole report (every format holds all findings). */
export function ExportButtons({ scanId, target, align = "end" }: { scanId: string; target: string; align?: "start" | "end" }) {
  const [busy, setBusy] = useState<ExportFormat | null>(null);
  const [error, setError] = useState<string | null>(null);

  const download = async (format: ExportFormat) => {
    setBusy(format);
    setError(null);
    try {
      await downloadReport(scanId, format, target);
    } catch (e) {
      setError(`${LABEL[format]}: ${e instanceof ApiError ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className={`flex flex-col items-start gap-1.5 ${align === "end" ? "sm:items-end" : ""}`}>
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Export the report">
        <span className="mr-1 text-xs font-medium text-muted">Export</span>
        {EXPORT_FORMATS.map((format) => {
          const available = canExport(scanId, format);
          return (
            <button
              key={format}
              type="button"
              onClick={() => download(format)}
              disabled={!available || busy !== null}
              title={available ? HINT[format] : "Run a real scan to export this format"}
              className="inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2.5 py-1.5 text-xs font-semibold text-ink transition-colors hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:border-line-strong disabled:hover:text-ink"
            >
              {busy === format ? (
                <span className="size-3 animate-spin rounded-full border-2 border-line-strong border-t-accent" aria-hidden="true" />
              ) : (
                <DownloadIcon />
              )}
              {LABEL[format]}
            </button>
          );
        })}
      </div>
      {error && (
        <p className="max-w-md text-xs text-danger-ink" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

function DownloadIcon() {
  return (
    <svg viewBox="0 0 16 16" className="size-3" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
      <path d="M8 2v8m0 0L5 7m3 3l3-3M3 13h10" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
