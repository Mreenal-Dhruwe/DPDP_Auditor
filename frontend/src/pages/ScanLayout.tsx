// Everything under /scans/:scanId (your scans) and /samples/:name (saved samples) reads one
// report, fetched once here. Nothing is loaded until a visitor opens one of these routes.
// Loading, unfinished (409), unknown or expired (404, 410) and unreachable states are explicit.
// A saved sample is only served under /samples/...; /scans/sample-... is "not found".

import { ScanLine } from "lucide-react";
import { createContext, useContext, useEffect } from "react";
import { Link, Outlet, useParams } from "react-router";
import { Heading, Notice, PageSkeleton } from "../components/ui";
import { ReviewProvider } from "../lib/reviews";
import { rememberScope } from "../lib/scope";
import { isSampleId } from "../lib/session";
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
  const { scanId: routeScan, name } = useParams();
  const saved = name !== undefined; // under /samples/:name
  const scanId = saved ? `sample-${name}` : (routeScan ?? "");
  const misrouted = !saved && isSampleId(scanId); // a sample id under /scans: not served there
  const { report, error } = useReport(misrouted ? "" : scanId);

  useEffect(() => {
    if (report && !saved) rememberScope({ scanId, target: report.target }); // never remember a saved sample
  }, [report, scanId, saved]);

  if (misrouted) return <ReportError scanId={scanId} status={404} message="" />;
  if (error) return <ReportError scanId={scanId} status={error.status} message={error.message} />;
  if (!report) return <PageSkeleton />;
  return (
    <Context.Provider value={{ scanId, report }}>
      <ReviewProvider key={scanId} scanId={scanId} findingIds={report.findings.map((f) => f.id)}>
        {saved && <SampleBanner name={name} />}
        <Outlet />
      </ReviewProvider>
    </Context.Provider>
  );
}

/** Shown on every screen of a saved sample, so it can never be mistaken for the visitor's scan. */
function SampleBanner({ name }: { name: string }) {
  return (
    <div className="samplebanner" role="note">
      <b>Saved sample, not your scan.</b>
      <span>
        A report saved earlier from the scanner command line ({name}). Nothing from your code is in it, it never expires, and nothing you do here
        changes it.
      </span>
      <Link to="/scan">Run your own scan</Link>
    </div>
  );
}

export function ReportError({ scanId, status, message }: { scanId: string; status: number; message: string }) {
  const sample = isSampleId(scanId);
  const unfinished = status === 409;
  const gone = status === 404 || status === 410;
  return (
    <section className="page narrow arrive">
      <Heading
        eyebrow={sample ? "Saved sample" : `Scan ${scanId.slice(0, 8)}`}
        title={
          unfinished
            ? "This scan has not finished"
            : sample && gone
              ? "Saved sample not found"
              : gone
                ? "This scan has expired or was not found"
                : "Could not load the report"
        }
      />
      <Notice kind={unfinished ? "info" : "error"} title={unfinished ? "Still running" : gone ? "Nothing to show" : "Unavailable"}>
        {sample && gone
          ? "There is no saved sample with that name. Saved samples are listed on the saved samples page."
          : gone
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
        <Link className="textlink" to="/samples">
          Browse saved samples
        </Link>
      </div>
    </section>
  );
}
