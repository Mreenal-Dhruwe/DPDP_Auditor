/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "mock": simulate the API with src/mock/report.json (npm run dev:mock). */
  readonly VITE_API_MODE?: string;
}
