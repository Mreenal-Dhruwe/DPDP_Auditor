// Workspace frame: charcoal rail, breadcrumb with the current scan's scope, skip link.
// Rail links follow the scan in the URL, else the last scan opened in this tab, else the
// bundled sample report.

import { BookOpen, ChevronRight, Columns3, FileChartColumn, LayoutDashboard, ScanLine } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useLayoutEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useParams } from "react-router";
import { getHealth, MOCK_MODE, SAMPLE_ID } from "../api";
import { isSample, useLastScope } from "../lib/scope";
import { ToastProvider } from "../lib/toast";

type Page = "overview" | "scan" | "findings" | "report" | "rules";

function pageOf(pathname: string): { page: Page; label: string } {
  if (pathname === "/scan" || pathname.endsWith("/progress")) return { page: "scan", label: "New scan" };
  if (pathname.startsWith("/rules")) return { page: "rules", label: "Rule catalogue" };
  if (/\/scans\/[^/]+\/findings/.test(pathname)) return { page: "findings", label: "Findings" };
  if (/\/scans\/[^/]+\/report/.test(pathname)) return { page: "report", label: "Report" };
  return { page: "overview", label: "Overview" };
}

export function Shell() {
  const location = useLocation();
  const { scanId: routeScan } = useParams();
  const last = useLastScope();
  const scanId = routeScan ?? last?.scanId ?? SAMPLE_ID;
  const target = last && last.scanId === scanId ? last.target : scanId === SAMPLE_ID ? "target_app" : "";
  const { page, label } = pageOf(location.pathname);
  const health = useHealth();

  // New page, top of the page - but opening or closing the evidence drawer is not a new page.
  const pageKey = (location.state as { board?: { pathname: string } } | null)?.board?.pathname ?? location.pathname;
  useLayoutEffect(() => {
    window.scrollTo(0, 0);
  }, [pageKey]);

  const nav = [
    { to: `/scans/${scanId}`, label: "Overview", icon: LayoutDashboard, end: true, page: "overview" },
    { to: "/scan", label: "New scan", icon: ScanLine, end: false, page: "scan" },
    { to: `/scans/${scanId}/findings`, label: "Findings", icon: Columns3, end: false, page: "findings" },
    { to: `/scans/${scanId}/report`, label: "Report", icon: FileChartColumn, end: false, page: "report" },
    { to: "/rules", label: "Rule catalogue", icon: BookOpen, end: false, page: "rules" },
  ] as const;

  return (
    <ToastProvider>
      <div className="workspace">
        <a className="skip" href="#content">
          Skip to content
        </a>
        <aside className="rail">
          <Link to="/" aria-label="DPDP Auditor home">
            <img src="/mark.svg" alt="" width="32" height="32" />
          </Link>
          <nav aria-label="Workspace">
            {nav.map((item) => (
              <NavLink key={item.label} to={item.to} end={item.end} aria-label={item.label} className={page === item.page ? "active" : ""}>
                {page === item.page && <motion.span layoutId="rail-active" className="rail-indicator" transition={{ type: "spring", stiffness: 520, damping: 42 }} />}
                <item.icon size={20} aria-hidden="true" />
                <span className="tip" aria-hidden="true">
                  {item.label}
                </span>
              </NavLink>
            ))}
          </nav>
          <div className="railfoot" title={health.title}>
            <i className={health.state} aria-hidden="true" />
            <span>{health.short}</span>
            <span className="sr-only">{health.title}</span>
          </div>
        </aside>
        <main id="content" tabIndex={-1}>
          <div className="crumb">
            <span>DPDP Auditor</span>
            <ChevronRight aria-hidden="true" />
            <span>{label}</span>
            {(page === "overview" || page === "findings" || page === "report") && (
              <span className={`scope${isSample(scanId) ? " sample" : ""}`}>
                {isSample(scanId) ? "Saved sample" : "Scan"}
                {target && (
                  <>
                    {" · "}
                    <b>{target}</b>
                  </>
                )}
              </span>
            )}
          </div>
          <Outlet />
        </main>
      </div>
    </ToastProvider>
  );
}

/** Service availability from GET /api/health, checked once per visit. */
function useHealth() {
  const [state, setState] = useState<"up" | "down" | "unknown">(MOCK_MODE ? "unknown" : "unknown");
  const [detail, setDetail] = useState("");
  useEffect(() => {
    let live = true;
    getHealth().then(
      (h) => live && (setState("up"), setDetail(`${h.detectors} detectors · v${h.version}`)),
      () => live && setState(MOCK_MODE ? "unknown" : "down"),
    );
    return () => {
      live = false;
    };
  }, []);
  if (MOCK_MODE) return { state, short: "mock", title: "Mock API: scans are simulated" };
  if (state === "up") return { state, short: "API", title: `Scanner API available (${detail})` };
  if (state === "down") return { state, short: "API", title: "Scanner API unreachable" };
  return { state, short: "API", title: "Checking the scanner API" };
}
