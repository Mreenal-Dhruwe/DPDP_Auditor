import { createRoot } from "react-dom/client";
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { MotionConfig } from "motion/react";
import Landing from "./Landing";
import { Shell, ReviewProvider, Miss } from "./ui";
import { Scan, Progress } from "./Scan";
import { Findings, Details, EvidenceDrawer } from "./Findings";
import { Reports, Rules } from "./Reports";
import "./styles.css";
import "./workspace.css";

const Dashboard = lazy(() => import("./Dashboard"));

function AppRoutes() {
  const location = useLocation(),
    board = location.state?.board;
  const overlay =
    board?.pathname === "/findings" &&
    location.pathname.startsWith("/findings/");
  return (
    <>
      <Routes location={overlay ? board : location}>
        <Route path="/" element={<Landing />} />
        <Route element={<Shell />}>
          <Route path="/scan" element={<Scan />} />
          <Route path="/scan/progress" element={<Progress />} />
          <Route path="/dashboard" element={
            <Suspense fallback={<p className="page" role="status">Loading overview…</p>}>
              <Dashboard />
            </Suspense>
          } />
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:id" element={<Details />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="*" element={<Miss />} />
        </Route>
      </Routes>
      {overlay && (
        <Routes>
          <Route path="/findings/:id" element={<EvidenceDrawer />} />
        </Routes>
      )}
    </>
  );
}
createRoot(document.getElementById("root")!).render(
  <BrowserRouter>
    <MotionConfig reducedMotion="user">
      <ReviewProvider>
        <AppRoutes />
      </ReviewProvider>
    </MotionConfig>
  </BrowserRouter>,
);

