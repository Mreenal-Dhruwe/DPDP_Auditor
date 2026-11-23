import { Link, NavLink, Outlet } from "react-router";
import { MOCK_MODE, SAMPLE_ID } from "../api";
import { DISCLAIMER } from "../types/contract";

export function Layout() {
  const nav = ({ isActive }: { isActive: boolean }) =>
    `rounded-md px-3 py-1.5 text-sm transition-colors ${isActive ? "bg-white/15 text-brand-ink" : "text-brand-ink/80 hover:bg-white/10 hover:text-brand-ink"}`;
  return (
    <div className="flex min-h-screen flex-col">
      <header className="bg-brand text-brand-ink">
        <div className="mx-auto flex max-w-7xl items-center gap-4 px-4 py-3 sm:px-6">
          <Link to="/" className="flex items-center gap-2.5 font-semibold tracking-tight">
            <ShieldIcon />
            <span>DPDP Compliance Auditor</span>
          </Link>
          {MOCK_MODE && (
            <span className="rounded border border-white/30 px-1.5 py-0.5 text-xs text-brand-ink/80">mock API</span>
          )}
          <nav className="ml-auto flex items-center gap-1">
            <NavLink to="/" end className={nav}>New scan</NavLink>
            <NavLink to={`/scans/${SAMPLE_ID}`} className={nav}>Sample report</NavLink>
          </nav>
        </div>
      </header>
      <main className="mx-auto w-full max-w-7xl flex-1 px-4 py-6 sm:px-6 sm:py-8">
        <Outlet />
      </main>
      <footer className="border-t border-line">
        <div className="mx-auto max-w-7xl px-4 py-4 text-xs text-muted sm:px-6">
          Maps findings to the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025. {DISCLAIMER}
        </div>
      </footer>
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 4l9 3.4v6.8c0 5.6-3.8 10.4-9 12.3-5.2-1.9-9-6.7-9-12.3V7.4z" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
      <path d="M12 15.5l2.8 2.8 5.2-5.6" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
