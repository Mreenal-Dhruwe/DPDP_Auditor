import { Link } from "react-router";
import { ErrorBox } from "./States";

/** Report could not be loaded: still running (409), unknown or expired (404), or no API. */
export function ReportError({ scanId, status, message }: { scanId: string; status: number; message: string }) {
  if (status === 409) {
    return (
      <div className="mx-auto max-w-xl py-8">
        <ErrorBox title="This scan has not finished">{message}</ErrorBox>
        <Link to={`/scans/${scanId}/progress`} className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
          Follow its progress
        </Link>
      </div>
    );
  }
  return (
    <div className="mx-auto max-w-xl py-8">
      <ErrorBox title={status === 404 ? "Report not found" : "Could not load the report"}>{message}</ErrorBox>
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
        Start a new scan
      </Link>
    </div>
  );
}
