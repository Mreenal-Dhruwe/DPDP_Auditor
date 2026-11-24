// Review status (Open / Triaged / In progress / Resolved) for each finding of a scan.
//
// A separate map keyed by scan id and the finding's stable id: moving a card never touches
// the scanner's fields (severity, confidence, legal mapping, evidence). The backend has no
// review store, so the map lives in this browser's localStorage and the UI says so. A team
// deployment would swap `load` / `save` for an authorised API with ownership checks.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

export const STATUSES = ["Open", "Triaged", "In progress", "Resolved"] as const;
export type ReviewStatus = (typeof STATUSES)[number];

interface Entry {
  status: ReviewStatus;
  at: string; // ISO time of the last change
}
type Reviews = Record<string, Entry>;

const keyOf = (scanId: string) => `dpdp.review.${scanId}`;

function load(scanId: string, ids: string[]): Reviews {
  let saved: Record<string, Partial<Entry>> = {};
  try {
    saved = JSON.parse(localStorage.getItem(keyOf(scanId)) ?? "{}") ?? {};
  } catch {
    /* unreadable or blocked storage: start fresh */
  }
  return Object.fromEntries(
    ids.map((id) => {
      const entry = saved[id];
      return [id, entry && STATUSES.includes(entry.status as ReviewStatus) ? { status: entry.status as ReviewStatus, at: entry.at ?? "" } : { status: "Open", at: "" }];
    }),
  );
}

interface ReviewApi {
  statusOf: (id: string) => ReviewStatus;
  /** Moves a finding; returns its previous status (for Undo). */
  move: (id: string, status: ReviewStatus) => ReviewStatus;
  counts: Record<ReviewStatus, number>;
  all: Reviews;
}

const ReviewContext = createContext<ReviewApi | null>(null);

export function ReviewProvider({ scanId, findingIds, children }: { scanId: string; findingIds: string[]; children: ReactNode }) {
  const idsKey = findingIds.join(",");
  const [reviews, setReviews] = useState<Reviews>(() => load(scanId, findingIds));
  useEffect(() => setReviews(load(scanId, idsKey ? idsKey.split(",") : [])), [scanId, idsKey]);

  useEffect(() => {
    try {
      localStorage.setItem(keyOf(scanId), JSON.stringify(reviews));
    } catch {
      /* the in-memory map keeps working */
    }
  }, [scanId, reviews]);

  // `move` may be called later from a toast's Undo: it reads the latest map, never a stale one
  const latest = useRef(reviews);
  latest.current = reviews;
  const statusOf = useCallback((id: string) => reviews[id]?.status ?? "Open", [reviews]);
  const move = useCallback((id: string, status: ReviewStatus) => {
    const previous = latest.current[id]?.status ?? "Open";
    if (previous !== status) {
      const next = { ...latest.current, [id]: { status, at: new Date().toISOString() } };
      latest.current = next;
      setReviews(next);
    }
    return previous;
  }, []);
  const counts = useMemo(() => {
    const result = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<ReviewStatus, number>;
    for (const entry of Object.values(reviews)) result[entry.status] += 1;
    return result;
  }, [reviews]);

  const value = useMemo(() => ({ statusOf, move, counts, all: reviews }), [statusOf, move, counts, reviews]);
  return <ReviewContext.Provider value={value}>{children}</ReviewContext.Provider>;
}

export function useReviews(): ReviewApi {
  const value = useContext(ReviewContext);
  if (!value) throw new Error("useReviews outside ReviewProvider");
  return value;
}
