// Which scan the workspace rail points at. The scan in the URL wins; otherwise the last one
// opened in this tab; otherwise the bundled sample report. In memory only: a reload starts
// empty (the scan itself is deleted from the server when the page is left).

import { useSyncExternalStore } from "react";
import { isSampleId } from "./session";

export interface Scope {
  scanId: string;
  target: string;
}

const EVENT = "dpdp-scope";
let current: Scope | null = null;

export function rememberScope(scope: Scope): void {
  if (current?.scanId === scope.scanId && current.target === scope.target) return;
  current = scope;
  window.dispatchEvent(new Event(EVENT));
}

function subscribe(onChange: () => void) {
  window.addEventListener(EVENT, onChange);
  return () => window.removeEventListener(EVENT, onChange);
}

export function useLastScope(): Scope | null {
  return useSyncExternalStore(subscribe, () => current, () => null);
}

export const isSample = isSampleId;
