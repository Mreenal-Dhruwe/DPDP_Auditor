import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { createBrowserRouter, Link } from "react-router";
import { RouterProvider } from "react-router/dom";
import { Layout } from "./components/Layout";
import { Dashboard } from "./pages/Dashboard";
import { FindingDetail } from "./pages/FindingDetail";
import { ScanProgress, Upload } from "./pages/Upload";
import "./index.css";

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { path: "/", element: <Upload /> },
      { path: "/scans/:scanId/progress", element: <ScanProgress /> },
      { path: "/scans/:scanId", element: <Dashboard /> },
      { path: "/scans/:scanId/findings/:findingId", element: <FindingDetail /> },
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
