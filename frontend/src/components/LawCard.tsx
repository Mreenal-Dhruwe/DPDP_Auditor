import type { Law, PenaltyCap } from "../types/contract";

/** "s.8(5)" -> "Section 8(5)" for reading; the short form stays visible in the table. */
function sectionName(ref: string): string {
  return ref.replace(/^s\./, "Section ");
}

export function LawCard({ law, penalty }: { law: Law; penalty: PenaltyCap }) {
  return (
    <div className="space-y-4 text-sm">
      {law.act.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">DPDP Act, 2023</h3>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {law.act.map((ref) => (
              <li key={ref} className="rounded-md border border-line bg-surface-2 px-2 py-0.5 font-medium text-ink">
                {sectionName(ref)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {law.rules.length > 0 && (
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">DPDP Rules, 2025</h3>
          <ul className="mt-1 flex flex-wrap gap-1.5">
            {law.rules.map((ref) => (
              <li key={ref} className="rounded-md border border-line bg-surface-2 px-2 py-0.5 font-medium text-ink">
                {ref}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div>
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">What the law requires</h3>
        <p className="mt-1 leading-relaxed text-ink">{law.requirement}</p>
      </div>
      <div className="rounded-lg bg-surface-2 px-3 py-2.5">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Maximum penalty</h3>
        <p className="mt-0.5 text-lg font-semibold tracking-tight text-ink">{penalty.cap}</p>
        <p className="text-xs text-ink-2">
          Schedule item {penalty.schedule_item}: {penalty.provision} (s.33)
        </p>
      </div>
    </div>
  );
}
