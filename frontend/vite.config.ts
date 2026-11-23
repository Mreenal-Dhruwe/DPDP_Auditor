import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Development: the browser only talks to Vite (http://localhost:5173), which forwards /api to
// the FastAPI backend, so no CORS is needed. API_URL overrides the backend address.
// `npm run dev:mock` (mode "mock", see .env.mock) needs no backend at all.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: process.env.API_URL ?? "http://localhost:8000", changeOrigin: true },
    },
  },
});
