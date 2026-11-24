// Saved samples (/samples): reports the scanner command line saved earlier, served by
// GET /api/samples. They are NOT the visitor's scans, never expire and are never loaded
// unless the visitor opens one from here (or from the landing page).

import { ArrowRight, Library } from "lucide-react";
import { useEffect, useState } from "react";
import { Link } from "react-router";
import { ApiError, getSamples, type SampleInfo } from "../api";
import { Heading, Notice, SeverityBadge } from "../components/ui";
import { formatDate } from "../lib/findings";
import { SEVERITIES } from "../types/contract";

export function SamplesIndex() {
  const [samples, setSamples] = useState<SampleInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    getSamples().then(
      (list) => live && setSamples(list),
      (e: unknown) => live && setError(e instanceof ApiError ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  return (
    <section className="page arrive">
      <Heading
        eyebrow="Saved samples"
        title="Saved sample reports"
        sub="Reports the scanner's command line saved earlier, so you can look around before scanning anything. They are not your scans: nothing in them comes from your code, they never expire, and nothing you do here changes them."
      />
      {error && (
        <Notice kind="error" title="Saved samples are unavailable">
          {error}
        </Notice>
      )}
      {!error && samples === null && <div className="skeleton" style={{ height: 150 }} aria-busy="true" />}
      {samples?.length === 0 && <Notice title="No saved samples">This server has no saved sample reports.</Notice>}
      {samples && samples.length > 0 && (
        <ul className="samplecards">
          {samples.map((s) => (
            <li key={s.id}>
              <Link to={`/samples/${s.name}`} className="samplecard">
                <span className="chip">
                  <Library aria-hidden="true" /> Saved sample, not your scan
                </span>
                <strong>{s.target}</strong>
                <span className="tabular samplemeta">
                  {s.total} findings · saved {formatDate(s.generated_at)}
                </span>
                <span className="samplesev">
                  {SEVERITIES.filter((sev) => s.by_severity[sev]).map((sev) => (
                    <span key={sev} className="tabular">
                      <SeverityBadge severity={sev} /> {s.by_severity[sev]}
                    </span>
                  ))}
                </span>
                <span className="open">
                  Open the saved report <ArrowRight aria-hidden="true" />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
      <p className="footnote">
        Want a report of your own code? <Link className="textlink" to="/scan">Start a scan</Link>.
      </p>
    </section>
  );
}
