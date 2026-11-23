// Which scan the workspace rail points at. The scan in the URL wins; otherwise the last one
// opened in this tab; otherwise the bundled sample report. Kept in sessionStorage (a
// per-tab convenience: the scan itself lives on the server).

import { useSyncExternalStore } from "react";
import { SAMPLE_ID } from "../api";

export interface Scope {
  scanId: string;
  target: string;
}

const KEY = "dpdp.scope";
const EVENT = "dpdp-scope";
let memory: Scope | null = null;

function read(): Scope | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    const value = raw ? (JSON.parse(raw) as Scope) : null;
    return value && typeof value.scanId === "string" && typeof value.target === "string" ? value : memory;
  } catch {
    return memory;
  }
}

let cached: Scope | null = read();

export function rememberScope(scope: Scope): void {
  if (cached?.scanId === scope.scanId && cached.target === scope.target) return;
  memory = cached = scope;
  try {
    sessionStorage.setItem(KEY, JSON.stringify(scope));
  } catch {
    /* in-memory only */
  }
  window.dispatchEvent(new Event(EVENT));
}

function subscribe(onChange: () => void) {
  window.addEventListener(EVENT, onChange);
  return () => window.removeEventListener(EVENT, onChange);
}

export function useLastScope(): Scope | null {
  return useSyncExternalStore(subscribe, () => cached, () => null);
}

export const isSample = (scanId: string) => scanId === SAMPLE_ID;
