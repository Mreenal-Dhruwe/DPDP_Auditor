import { SEVERITY_LABEL } from "../lib/findings";
import type { Confidence, Severity } from "../types/contract";

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/** Colour is never alone: the dot always sits next to the severity's name. */
export function SeverityBadge({ severity, size = "sm" }: { severity: Severity; size?: "sm" | "lg" }) {
  const big = size === "lg";
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border border-line bg-surface font-medium text-ink ${big ? "px-3 py-1 text-sm" : "px-2 py-0.5 text-xs"}`}
    >
      <span className={`${SEVERITY_DOT[severity]} ${big ? "size-2.5" : "size-2"} rounded-full`} aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const CONFIDENCE_BARS: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/** How sure the detector is that this is a real problem (separate from how bad it is). */
export function ConfidenceTag({ confidence }: { confidence: Confidence }) {
  const filled = CONFIDENCE_BARS[confidence];
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-ink-2" title={`Detector confidence: ${confidence}`}>
      <span className="flex items-end gap-0.5" aria-hidden="true">
        {[1, 2, 3].map((n) => (
          <span key={n} className={`w-1 rounded-sm ${n <= filled ? "bg-ink-2" : "bg-line-strong"}`} style={{ height: 4 + n * 3 }} />
        ))}
      </span>
      {confidence}
    </span>
  );
}
