/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "mock": simulate the API with src/mock/mockApi.ts (npm run dev:mock only; never in production). */
  readonly VITE_API_MODE?: string;
}
