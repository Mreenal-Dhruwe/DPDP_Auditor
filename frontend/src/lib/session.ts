// What this tab knows about its own scans, in memory only.
//
// Nothing here touches localStorage or sessionStorage: a reload, a new tab or a direct visit
// starts empty. Each scan this tab starts is registered with the delete token the server
// returned once. When the page is left (pagehide: reload, close, navigation away) the tab
// asks the server to delete every scan it created, with navigator.sendBeacon. A beacon can
// only POST, so the endpoint is POST /api/scans/{id}/delete with {"token": ...}; the server
// refuses a wrong token. Anything the beacon misses is deleted by the server's 30-minute TTL.

/** "sample-<name>": a saved report served by /api/samples under /samples/<name>. Real scan ids
 *  are 32 hex characters, so the two can never collide. */
export const isSampleId = (scanId: string) => scanId.startsWith("sample-");

interface Owned {
  token: string;
  expiresAt: string | null;
}
const owned = new Map<string, Owned>();

export function registerScan(scanId: string, token: string): void {
  owned.set(scanId, { token, expiresAt: null });
}
export const ownsScan = (scanId: string) => owned.has(scanId);
export function setExpiry(scanId: string, expiresAt: string): void {
  const entry = owned.get(scanId);
  if (entry) entry.expiresAt = expiresAt;
}
export const expiryOf = (scanId: string): string | null => owned.get(scanId)?.expiresAt ?? null;

let installed = false;
/** Delete this tab's scans on the server when the page is left. Call once at start-up. */
export function installLeaveCleanup(): void {
  if (installed || typeof window === "undefined") return;
  installed = true;
  window.addEventListener("pagehide", () => {
    for (const [scanId, { token }] of owned) {
      if (token === "mock") continue; // the mock API has no server
      // text/plain keeps it a "simple" request: no preflight, and the server parses the JSON itself
      navigator.sendBeacon(`/api/scans/${encodeURIComponent(scanId)}/delete`, new Blob([JSON.stringify({ token })], { type: "text/plain" }));
    }
  });
}
