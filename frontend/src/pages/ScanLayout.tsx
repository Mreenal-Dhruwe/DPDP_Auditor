// Everything under /scans/:scanId (except progress) reads one report, fetched once here.
// Loading, unfinished (409), unknown or expired (404) and unreachable states are explicit.

import { ScanLine } from "lucide-react";
import { createContext, useContext, useEffect } from "react";
import { Link, Outlet, useParams } from "react-router";
import { SAMPLE_ID } from "../api";
import { Heading, Notice, PageSkeleton } from "../components/ui";
import { ReviewProvider } from "../lib/reviews";
import { rememberScope } from "../lib/scope";
import { useReport } from "../lib/useReport";
import type { Report } from "../types/contract";

interface ScanContext {
  scanId: string;
  report: Report;
}
const Context = createContext<ScanContext | null>(null);

export function useScan(): ScanContext {
  const value = useContext(Context);
  if (!value) throw new Error("useScan outside ScanLayout");
  return value;
}

export function ScanLayout() {
  const { scanId = "" } = useParams();
  const { report, error } = useReport(scanId);

  useEffect(() => {
    if (report) rememberScope({ scanId, target: report.target });
  }, [report, scanId]);

  if (error) return <ReportError scanId={scanId} status={error.status} message={error.message} />;
  if (!report) return <PageSkeleton />;
  return (
    <Context.Provider value={{ scanId, report }}>
      <ReviewProvider key={scanId} scanId={scanId} findingIds={report.findings.map((f) => f.id)}>
        <Outlet />
      </ReviewProvider>
    </Context.Provider>
  );
}

export function ReportError({ scanId, status, message }: { scanId: string; status: number; message: string }) {
  const unfinished = status === 409;
  const gone = status === 404 || status === 410;
  return (
    <section className="page narrow arrive">
      <Heading
        eyebrow={`Scan ${scanId.slice(0, 8)}`}
        title={unfinished ? "This scan has not finished" : gone ? "This scan has expired or was not found" : "Could not load the report"}
      />
      <Notice kind={unfinished ? "info" : "error"} title={unfinished ? "Still running" : gone ? "Nothing to show" : "Unavailable"}>
        {gone
          ? "Scans belong to the tab that started them. They are cleared when you reload or leave, and the server deletes them 30 minutes after they were created. Start a new scan, or open a saved sample."
          : message}
      </Notice>
      <div className="formactions">
        {unfinished ? (
          <Link className="btn mint" to={`/scans/${scanId}/progress`}>
            Follow its progress
          </Link>
        ) : (
          <Link className="btn mint" to="/scan">
            <ScanLine aria-hidden="true" />
            Start a new scan
          </Link>
        )}
        <Link className="textlink" to={`/scans/${SAMPLE_ID}`}>
          Open the saved sample report
        </Link>
      </div>
    </section>
  );
}
