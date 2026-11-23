import type { ReactNode } from "react";

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 py-16 text-ink-2" role="status">
      <span className="size-4 animate-spin rounded-full border-2 border-line-strong border-t-accent" aria-hidden="true" />
      {label}
    </div>
  );
}

export function ErrorBox({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="rounded-lg border border-danger-ink/30 bg-danger-soft px-4 py-3 text-sm text-ink" role="alert">
      <p className="font-medium text-danger-ink">{title}</p>
      {children && <div className="mt-1 text-ink-2">{children}</div>}
    </div>
  );
}

export function Card({ title, aside, children, className = "" }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-xl border border-line bg-surface ${className}`}>
      {title && (
        <div className="flex items-center justify-between gap-3 border-b border-line px-4 py-3 sm:px-5">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {aside}
        </div>
      )}
      <div className="px-4 py-4 sm:px-5">{children}</div>
    </section>
  );
}
