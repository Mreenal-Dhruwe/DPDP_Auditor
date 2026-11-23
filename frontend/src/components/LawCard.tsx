// The legal mapping exactly as the rules file states it: Act sections, Rules, requirement
// and the s.33 penalty cap. Indicative, never a compliance verdict.

import { ShieldCheck } from "lucide-react";
import type { Law, PenaltyCap } from "../types/contract";

const sectionName = (ref: string) => ref.replace(/^s\./, "Section ");

export function LawCard({ law, penalty, disclaimer }: { law: Law; penalty: PenaltyCap; disclaimer: string }) {
  return (
    <div className="panel lawcard">
      <h2 className="type-pixel">
        <ShieldCheck aria-hidden="true" /> Provision mapping
      </h2>
      {law.act.length > 0 && (
        <div className="lawgroup">
          <span className="fieldlabel">DPDP Act, 2023</span>
          <ul className="chips">
            {law.act.map((ref) => (
              <li key={ref} className="chip law">
                {sectionName(ref)}
              </li>
            ))}
          </ul>
        </div>
      )}
      {law.rules.length > 0 && (
        <div className="lawgroup">
          <span className="fieldlabel">DPDP Rules, 2025</span>
          <ul className="chips">
            {law.rules.map((ref) => (
              <li key={ref} className="chip law">
                {ref}
              </li>
            ))}
          </ul>
        </div>
      )}
      <div className="lawgroup">
        <span className="fieldlabel">What the law requires</span>
        <p className="requirement">{law.requirement}</p>
      </div>
      <div className="penalty">
        <span className="fieldlabel">Maximum penalty</span>
        <strong>{penalty.cap}</strong>
        <small>
          Schedule item {penalty.schedule_item}: {penalty.provision} (s.33). An upper limit set by the Act, not an estimate.
        </small>
      </div>
      <small className="disclaimer">{disclaimer}</small>
    </div>
  );
}
