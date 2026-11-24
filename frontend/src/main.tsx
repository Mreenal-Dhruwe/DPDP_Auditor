import { MotionConfig } from "motion/react";
import { lazy, StrictMode, Suspense, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Link } from "react-router";
import { RouterProvider } from "react-router/dom";
import { Shell } from "./components/Shell";
import { Heading, PageSkeleton } from "./components/ui";
import { Landing } from "./landing/Landing";
import { installLeaveCleanup } from "./lib/session";
import { NewScan, ScanProgress } from "./pages/Scan";
import { ScanLayout } from "./pages/ScanLayout";
import "./index.css";

// Report screens (and Recharts) load on demand, so the landing and scan pages stay small.
const Overview = lazy(() => import("./pages/Overview").then((m) => ({ default: m.Overview })));
const ReportPage = lazy(() => import("./pages/Report").then((m) => ({ default: m.ReportPage })));
const Rules = lazy(() => import("./pages/Rules").then((m) => ({ default: m.Rules })));
const FindingsRoute = lazy(() => import("./pages/Findings").then((m) => ({ default: m.FindingsRoute })));
const page = (element: ReactNode) => <Suspense fallback={<PageSkeleton />}>{element}</Suspense>;

const router = createBrowserRouter([
  { path: "/", element: <Landing /> },
  {
    element: <Shell />,
    children: [
      { path: "/scan", element: <NewScan /> },
      { path: "/scans/:scanId/progress", element: <ScanProgress /> },
      {
        path: "/scans/:scanId",
        element: <ScanLayout />,
        children: [
          { index: true, element: page(<Overview />) },
          // one route for board and drawer: the board stays mounted while the drawer opens
          { path: "findings/:findingId?", element: page(<FindingsRoute />) },
          { path: "report", element: page(<ReportPage />) },
        ],
      },
      { path: "/rules", element: page(<Rules />) },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

function NotFound() {
  return (
    <section className="page narrow arrive">
      <Heading eyebrow="404" title="Page not found" sub="This address has no matching view." />
      <Link className="btn mint" to="/scan">
        Start a new scan
      </Link>
    </section>
  );
}

installLeaveCleanup(); // pagehide: delete this tab's scans on the server

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MotionConfig reducedMotion="user">
      <RouterProvider router={router} />
    </MotionConfig>
  </StrictMode>,
);
