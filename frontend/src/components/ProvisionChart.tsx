// Findings per DPDP provision (one series: one colour, no legend). Values sit at the bar
// tips; the tooltip adds the severity breakdown; clicking a bar filters the table. The
// findings table below is the chart's table view.

import { useReducedMotion } from "motion/react";
import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { compareProvisions, provisionsOf, SEVERITY_LABEL } from "../lib/findings";
import type { Finding, Severity } from "../types/contract";
import { SEVERITIES } from "../types/contract";

type Kind = "act" | "rules";
interface Row {
  provision: string;
  count: number;
  bySeverity: Record<Severity, number>;
}
const ROW_PX = 28;

export function ProvisionChart({ findings, selected, onSelect }: { findings: Finding[]; selected: string; onSelect: (p: string) => void }) {
  const [kind, setKind] = useState<Kind>("act");
  const rows = useMemo(() => provisionRows(findings, kind), [findings, kind]);
  const reduced = useReducedMotion();

  return (
    <div className="provchart">
      <div className="between">
        <h3 className="type-pixel">Findings by DPDP provision</h3>
        <div className="tabs compact" role="group" aria-label="Provision type">
          {(["act", "rules"] as const).map((k) => (
            <button key={k} type="button" aria-pressed={kind === k} onClick={() => setKind(k)}>
              {k === "act" ? "Act sections" : "Rules"}
            </button>
          ))}
        </div>
      </div>
      {rows.length === 0 ? (
        <p className="emptyrow">No findings cite {kind === "act" ? "an Act section" : "a Rule"}.</p>
      ) : (
        <ResponsiveContainer width="100%" height={rows.length * ROW_PX + 8}>
          <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 34, bottom: 4, left: 0 }} barCategoryGap={6}>
            <XAxis type="number" hide allowDecimals={false} domain={[0, "dataMax"]} />
            <YAxis type="category" dataKey="provision" width={92} tickLine={false} axisLine={{ stroke: "#3a3b42" }} tick={{ fill: "#b6b7c2", fontSize: 12 }} />
            <Tooltip cursor={{ fill: "#ffffff0a" }} content={<ProvisionTooltip />} isAnimationActive={false} />
            <Bar
              dataKey="count"
              radius={[0, 4, 4, 0]}
              maxBarSize={16}
              isAnimationActive={!reduced}
              animationDuration={420}
              cursor="pointer"
              onClick={(entry: { payload?: Row }) => entry.payload && onSelect(entry.payload.provision === selected ? "" : entry.payload.provision)}
            >
              {rows.map((row) => (
                <Cell key={row.provision} fill="#b8a0ec" fillOpacity={!selected || selected === row.provision ? 1 : 0.3} />
              ))}
              <LabelList dataKey="count" position="right" fill="#c7c8cf" fontSize={12} />
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
      <p className="charthint">
        {selected ? (
          <>
            Showing findings that cite <b>{selected}</b>.{" "}
            <button type="button" className="textlink" onClick={() => onSelect("")}>
              Show all
            </button>
          </>
        ) : (
          "Click a bar to filter the findings below."
        )}
      </p>
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
    <div className="charttip">
      <p>
        <b className="tabular">{row.count}</b> finding{row.count === 1 ? "" : "s"} citing {row.provision}
      </p>
      <ul>
        {SEVERITIES.filter((s) => row.bySeverity[s]).map((s) => (
          <li key={s} className={`sev-${s}`}>
            <i aria-hidden="true" />
            <b className="tabular">{row.bySeverity[s]}</b> {SEVERITY_LABEL[s]}
          </li>
        ))}
      </ul>
    </div>
  );
}
