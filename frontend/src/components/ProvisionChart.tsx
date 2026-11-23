// Findings per DPDP provision: one series, so one colour and no legend (the title names it).
// Bars carry their value at the tip; the tooltip adds the severity breakdown. Clicking a
// bar filters the findings table to that provision; the table is the chart's table view.

import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { compareProvisions, provisionsOf, SEVERITY_LABEL } from "../lib/findings";
import type { Finding, Severity } from "../types/contract";
import { SEVERITIES } from "../types/contract";
import { SEVERITY_DOT } from "./SeverityBadge";

type Kind = "act" | "rules";
interface Row {
  provision: string;
  count: number;
  bySeverity: Record<Severity, number>;
}

const ROW_PX = 30;

export function ProvisionChart({ findings, selected, onSelect }: { findings: Finding[]; selected: string; onSelect: (p: string) => void }) {
  const [kind, setKind] = useState<Kind>("act");
  const rows = useMemo(() => provisionRows(findings, kind), [findings, kind]);

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-3">
        <p className="text-xs text-muted">Findings citing each provision. Click a bar to filter the table.</p>
        <div className="inline-flex shrink-0 rounded-lg border border-line p-0.5 text-xs" role="group" aria-label="Provision type">
          {(["act", "rules"] as const).map((k) => (
            <button
              key={k}
              type="button"
              aria-pressed={kind === k}
              onClick={() => setKind(k)}
              className={`rounded-md px-2.5 py-1 font-medium transition-colors ${kind === k ? "bg-accent-soft text-accent" : "text-ink-2 hover:text-ink"}`}
            >
              {k === "act" ? "Act sections" : "Rules"}
            </button>
          ))}
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted">No findings cite {kind === "act" ? "an Act section" : "a Rule"}.</p>
      ) : (
        <ResponsiveContainer width="100%" height={rows.length * ROW_PX + 8}>
          <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 36, bottom: 4, left: 0 }} barCategoryGap={6}>
            <XAxis type="number" hide allowDecimals={false} domain={[0, "dataMax"]} />
            <YAxis
              type="category"
              dataKey="provision"
              width={96}
              tickLine={false}
              axisLine={{ stroke: "var(--line-strong)" }}
              tick={{ fill: "var(--ink-2)", fontSize: 12 }}
            />
            <Tooltip cursor={{ fill: "var(--accent-soft)" }} content={<ProvisionTooltip />} isAnimationActive={false} />
            <Bar
              dataKey="count"
              radius={[0, 4, 4, 0]}
              maxBarSize={18}
              isAnimationActive={false}
              cursor="pointer"
              onClick={(entry: { payload?: Row }) => entry.payload && onSelect(entry.payload.provision === selected ? "" : entry.payload.provision)}
            >
              {rows.map((row) => (
                <Cell key={row.provision} fill="var(--series-1)" fillOpacity={!selected || selected === row.provision ? 1 : 0.35} />
              ))}
              <LabelList dataKey="count" position="right" fill="var(--ink-2)" fontSize={12} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

function provisionRows(findings: Finding[], kind: Kind): Row[] {
  const rows = new Map<string, Row>();
  for (const f of findings) {
    for (const p of provisionsOf(f)) {
      if (p.startsWith("Rule") !== (kind === "rules")) continue;
      const row = rows.get(p) ?? { provision: p, count: 0, bySeverity: Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number> };
      row.count += 1;
      row.bySeverity[f.severity] += 1;
      rows.set(p, row);
    }
  }
  return [...rows.values()].sort((a, b) => b.count - a.count || compareProvisions(a.provision, b.provision));
}

function ProvisionTooltip({ active, payload }: { active?: boolean; payload?: { payload: Row }[] }) {
  const row = active ? payload?.[0]?.payload : undefined;
  if (!row) return null;
  return (
    <div className="rounded-lg border border-line bg-surface px-3 py-2 text-xs shadow-md">
      <p className="text-base font-semibold text-ink">
        {row.count} <span className="text-xs font-normal text-ink-2">finding{row.count === 1 ? "" : "s"} citing {row.provision}</span>
      </p>
      <ul className="mt-1 space-y-0.5">
        {SEVERITIES.filter((s) => row.bySeverity[s]).map((s) => (
          <li key={s} className="flex items-center gap-1.5 text-ink-2">
            <span className={`h-0.5 w-3 ${SEVERITY_DOT[s]}`} aria-hidden="true" />
            <span className="tabular font-medium text-ink">{row.bySeverity[s]}</span> {SEVERITY_LABEL[s]}
          </li>
        ))}
      </ul>
    </div>
  );
}
