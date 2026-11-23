// Native select for a finding's review status: works with keyboard, touch and screen
// readers on every view (board card, list, detail). Moving only changes review metadata.

import { STATUSES, useReviews, type ReviewStatus } from "../lib/reviews";
import { useToast } from "../lib/toast";

export function useMoveWithUndo() {
  const { move } = useReviews();
  const toast = useToast();
  return (id: string, title: string, status: ReviewStatus) => {
    const previous = move(id, status);
    if (previous === status) return;
    toast({ message: `“${title}” moved to ${status}`, action: { label: "Undo", run: () => move(id, previous) } });
  };
}

export function ReviewSelect({ id, title, compact = false }: { id: string; title: string; compact?: boolean }) {
  const { statusOf } = useReviews();
  const moveWithUndo = useMoveWithUndo();
  return (
    <select
      className={compact ? "reviewselect compact" : "reviewselect"}
      aria-label={`Review status for ${title}`}
      value={statusOf(id)}
      onChange={(e) => moveWithUndo(id, title, e.target.value as ReviewStatus)}
    >
      {STATUSES.map((s) => (
        <option key={s}>{s}</option>
      ))}
    </select>
  );
}
