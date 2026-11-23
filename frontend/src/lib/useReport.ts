import { useEffect, useState } from "react";
import { ApiError, getReport } from "../api";
import type { Report } from "../types/contract";

type State = { report: Report | null; error: ApiError | null };

/** The report for a scan, fetched once and cached by api.ts. */
export function useReport(scanId: string) {
  const [state, setState] = useState<State & { scanId: string }>({ scanId, report: null, error: null });
  useEffect(() => {
    let live = true;
    getReport(scanId).then(
      (report) => live && setState({ scanId, report, error: null }),
      (error: unknown) =>
        live && setState({ scanId, report: null, error: error instanceof ApiError ? error : new ApiError(0, String(error)) }),
    );
    return () => {
      live = false;
    };
  }, [scanId]);
  const current = state.scanId === scanId;
  return { report: current ? state.report : null, error: current ? state.error : null };
}
