// Where a report lives. A scan you started: /scans/<id>. A saved sample: /samples/<name>,
// the only place saved samples are served. Both share the same screens under that base.

import { isSampleId } from "./session";

export const sampleName = (scanId: string) => scanId.slice("sample-".length);

/** "/scans/<id>" for a live scan, "/samples/<name>" for a saved sample. */
export function scanBase(scanId: string): string {
  return isSampleId(scanId) ? `/samples/${encodeURIComponent(sampleName(scanId))}` : `/scans/${scanId}`;
}
