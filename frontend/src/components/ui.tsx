// Shared presentation primitives (design system: dpdp-design-handoff/docs/DESIGN_SYSTEM.md).

import { AlertTriangle, Info } from "lucide-react";
import type { ReactNode } from "react";
import { SEVERITY_LABEL } from "../lib/findings";
import type { Confidence, Severity } from "../types/contract";

export function Heading({ title, sub, eyebrow, children }: { title: ReactNode; sub?: ReactNode; eyebrow?: ReactNode; children?: ReactNode }) {
  return (
    <header className="heading">
      <div>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {children}
    </header>
  );
}

/** Severity as the scanner reported it: the colour never stands alone. */
export function SeverityBadge({ severity, large = false }: { severity: Severity; large?: boolean }) {
  return (
    <span className={`badge sev-${severity}${large ? " lg" : ""}`}>
      <i aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const CONFIDENCE_LEVEL: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/** Detection confidence: how sure the detector is, independent of severity. */
export function ConfidenceMeter({ confidence, label = true }: { confidence: Confidence; label?: boolean }) {
  const level = CONFIDENCE_LEVEL[confidence];
  return (
    <span className="confidence" title={`Detection confidence: ${confidence}`}>
      <span className="bars" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <i key={n} className={n <= level ? "on" : ""} />
        ))}
      </span>
      {label ? confidence : <span className="sr-only">{confidence} confidence</span>}
    </span>
  );
}

export function Notice({ kind = "info", title, children }: { kind?: "info" | "error"; title: ReactNode; children?: ReactNode }) {
  const Icon = kind === "error" ? AlertTriangle : Info;
  return (
    <div className={`notice ${kind}`} role={kind === "error" ? "alert" : "status"}>
      <Icon aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        {children && <p>{children}</p>}
      </div>
    </div>
  );
}

/** Placeholder shapes while a report loads: the layout does not jump when it arrives. */
export function PageSkeleton({ label = "Loading the report…" }: { label?: string }) {
  return (
    <section className="page" aria-busy="true">
      <p className="sr-only" role="status">
        {label}
      </p>
      <div className="skeleton" style={{ height: 14, width: 120 }} />
      <div className="skeleton" style={{ height: 46, width: "min(520px, 80%)", marginTop: 12 }} />
      <div className="skeleton-grid">
        <div className="skeleton" style={{ height: 260 }} />
        <div className="skeleton" style={{ height: 260 }} />
      </div>
      <div className="skeleton" style={{ height: 180, marginTop: 18 }} />
    </section>
  );
}
