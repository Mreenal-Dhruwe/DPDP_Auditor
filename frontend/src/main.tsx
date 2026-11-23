import { lazy, StrictMode, Suspense, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Link } from "react-router";
import { RouterProvider } from "react-router/dom";
import { Layout } from "./components/Layout";
import { Loading } from "./components/States";
import { ScanProgress, Upload } from "./pages/Upload";
import "./index.css";

// The report screens (and Recharts) load on demand, so the upload page stays small.
const Dashboard = lazy(() => import("./pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const FindingDetail = lazy(() => import("./pages/FindingDetail").then((m) => ({ default: m.FindingDetail })));
const page = (element: ReactNode) => <Suspense fallback={<Loading />}>{element}</Suspense>;

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <Upload /> },
      { path: "/scans/:scanId/progress", element: <ScanProgress /> },
      { path: "/scans/:scanId", element: page(<Dashboard />) },
      { path: "/scans/:scanId/findings/:findingId", element: page(<FindingDetail />) },
      { path: "*", element: <NotFound /> },
    ],
  },
]);

function NotFound() {
  return (
    <div className="py-16">
      <h1 className="text-xl font-semibold">Page not found</h1>
      <Link to="/" className="mt-2 inline-block text-accent hover:underline">Start a new scan</Link>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
);
