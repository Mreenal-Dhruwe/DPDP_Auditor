// Report downloads from the server (GET /api/scan/{id}/report.{fmt}). Fetched first, so a
// server answer such as "PDF needs Pango" (501) is shown instead of a broken download.

import { Download, LoaderCircle } from "lucide-react";
import { useState } from "react";
import { ApiError, canExport, downloadReport, EXPORT_FORMATS, type ExportFormat } from "../api";

const LABEL: Record<ExportFormat, string> = { html: "HTML", pdf: "PDF", sarif: "SARIF", json: "JSON" };
const HINT: Record<ExportFormat, string> = {
  html: "Self-contained report to open in a browser or share",
  pdf: "Printable report (the server needs WeasyPrint's Pango libraries; the Docker image has them)",
  sarif: "SARIF 2.1.0 for GitHub code scanning and IDEs",
  json: "The master report.json",
};

export function ExportButtons({ scanId, target }: { scanId: string; target: string }) {
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
    <div className="exports">
      <div className="exportgrid" role="group" aria-label="Export the report">
        {EXPORT_FORMATS.map((format) => {
          const available = canExport(scanId, format);
          return (
            <button
              key={format}
              type="button"
              className="btn secondary small"
              onClick={() => download(format)}
              disabled={!available || busy !== null}
              title={available ? HINT[format] : "Run a real scan to export this format"}
            >
              {busy === format ? <LoaderCircle className="spin" aria-hidden="true" /> : <Download aria-hidden="true" />}
              {LABEL[format]}
            </button>
          );
        })}
      </div>
      {error && (
        <p className="exporterror" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}
