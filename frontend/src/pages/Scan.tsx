// New scan (/scan) and its progress (/scans/:id/progress), on the real API:
// POST /api/scan (zip upload or Git URL), then GET /api/scan/{id} every second.

import { Check, Circle, FileArchive, GitBranch, LoaderCircle, ScanLine, UploadCloud, X } from "lucide-react";
import { useEffect, useRef, useState, type DragEvent, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ApiError, getSamples, getScanStatus, SAMPLE_ID, startGitScan, startZipScan, type SampleInfo } from "../api";
import { Heading, Notice } from "../components/ui";
import { rememberScope } from "../lib/scope";
import { setExpiry } from "../lib/session";
import type { ScanStatus } from "../types/contract";

const JUICE_SHOP = "https://github.com/juice-shop/juice-shop";
type Mode = "zip" | "git";

/** Same rules as the backend (scanner/ingest.py validate_git_url), checked before sending. */
function gitUrlProblem(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (url.protocol !== "https:") return "Only https URLs are accepted.";
    if (url.username || url.password) return "Remove the credentials from the URL.";
    if (url.search || url.hash || url.pathname.split("/").filter(Boolean).length < 2)
      return "Use the repository URL: https://host/owner/repository";
    return null;
  } catch {
    return "Enter an https repository URL, e.g. https://github.com/owner/repository";
  }
}

export function NewScan() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<Mode>("zip");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [over, setOver] = useState(false);
  const [samples, setSamples] = useState<SampleInfo[]>([]);
  useEffect(() => {
    let live = true;
    getSamples().then((list) => live && setSamples(list), () => {});
    return () => {
      live = false;
    };
  }, []);

  const choose = (chosen: File | undefined) => {
    setError(null);
    if (!chosen) return;
    if (!chosen.name.toLowerCase().endsWith(".zip") || chosen.size === 0) {
      setFile(null);
      setError(`"${chosen.name}" is not a non-empty .zip file. Zip the project folder first.`);
      return;
    }
    setFile(chosen);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (mode === "zip" && !file) return setError("Choose a .zip of the project to scan.");
    if (mode === "git") {
      const problem = gitUrlProblem(url);
      if (problem) return setError(problem);
    }
    setBusy(true);
    setError(null);
    try {
      const { scan_id } = mode === "zip" ? await startZipScan(file!) : await startGitScan(url.trim());
      navigate(`/scans/${scan_id}/progress`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <section className="page arrive">
      <Heading
        eyebrow="Read, never run"
        title="New scan"
        sub="Upload the source code or point to a public Git repository. Every finding is mapped to the DPDP Act, 2023 and the DPDP Rules, 2025."
      />
      <div className="scan-grid">
        <form className="panel scanform" onSubmit={submit} noValidate>
          <h2 className="type-pixel">Repository source</h2>
          <div className="tabs" role="group" aria-label="Source">
            {(["zip", "git"] as const).map((m) => (
              <button
                type="button"
                key={m}
                aria-pressed={mode === m}
                disabled={busy}
                onClick={() => {
                  setMode(m);
                  setError(null);
                }}
              >
                {m === "zip" ? <FileArchive aria-hidden="true" /> : <GitBranch aria-hidden="true" />}
                {m === "zip" ? "ZIP archive" : "Git URL"}
              </button>
            ))}
          </div>

          {mode === "zip" ? (
            <label
              className={`dropzone${over ? " over" : ""}${file ? " chosen" : ""}`}
              onDragOver={(e: DragEvent) => {
                e.preventDefault();
                setOver(true);
              }}
              onDragLeave={() => setOver(false)}
              onDrop={(e: DragEvent) => {
                e.preventDefault();
                setOver(false);
                if (!busy) choose(e.dataTransfer.files[0]);
              }}
            >
              <input
                type="file"
                accept=".zip,application/zip"
                aria-label="Choose a .zip of the project"
                data-testid="zip-input"
                disabled={busy}
                onChange={(e) => {
                  choose(e.target.files?.[0]);
                  e.target.value = "";
                }}
              />
              <UploadCloud size={34} aria-hidden="true" />
              <strong>{file ? file.name : "Drop a .zip of the project here"}</strong>
              <span>{file ? `${formatBytes(file.size)} · choose a different file` : "or browse files"}</span>
            </label>
          ) : (
            <label className="field">
              <span>Repository URL</span>
              <input
                type="url"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                placeholder="https://github.com/owner/repository"
                value={url}
                disabled={busy}
                onChange={(e) => {
                  setUrl(e.target.value);
                  setError(null);
                }}
              />
              <small>Public https repositories on GitHub, GitLab or Bitbucket. The clone is shallow and never executed.</small>
            </label>
          )}

          {error && (
            <div className="formerror">
              <Notice kind="error" title="Could not start the scan">
                {error}
              </Notice>
            </div>
          )}

          <div className="formactions">
            <button className="btn mint" type="submit" disabled={busy}>
              {busy ? <LoaderCircle className="spin" aria-hidden="true" /> : <ScanLine aria-hidden="true" />}
              {busy ? "Starting…" : "Start scan"}
            </button>
            <button
              type="button"
              className="textlink"
              disabled={busy}
              onClick={() => {
                setMode("git");
                setUrl(JUICE_SHOP);
                setError(null);
              }}
            >
              Use OWASP Juice Shop
            </button>
          </div>
        </form>

        <aside className="scaninfo">
          <h2 className="type-pixel">How the scan runs</h2>
          {[
            ["Ingest", "Unpack the zip or clone the repository into a temporary folder, deleted after the scan."],
            ["Find personal data", "Field names, synonyms and value patterns: Aadhaar, PAN, phone, email and more."],
            ["Check 28 rules", "Patterns, code structure, missing safeguards and configuration."],
            ["Map to the law", "Each finding cites the Act section, the Rule and the penalty cap."],
          ].map(([title, text], i) => (
            <div key={title}>
              <span>{String(i + 1).padStart(2, "0")}</span>
              <p>
                <strong>{title}</strong>
                {text}
              </p>
            </div>
          ))}
          <small>
            Evidence in reports is masked. Scans are private to this tab: they are cleared when you reload or leave, and the server deletes them after 30 minutes.
          </small>
          <div className="samplelist" id="samples">
            <h2 className="type-pixel">Saved samples</h2>
            <p>
              Reports saved earlier from the command line. They are <b>not live scans</b> and are never deleted.
            </p>
            <ul>
              {(samples.length ? samples : [{ id: SAMPLE_ID, name: SAMPLE_ID, target: "target_app", total: 16, generated_at: "" } as SampleInfo]).map((s) => (
                <li key={s.id}>
                  <Link to={`/scans/${s.id}`}>
                    <strong>{s.target}</strong>
                    <small>
                      {s.total} findings · saved sample
                    </small>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        </aside>
      </div>
    </section>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// --- progress ------------------------------------------------------------------------------

const STAGES: Record<string, [string, string]> = {
  queued: ["Queued", "Waiting for the scanner"],
  unpacking: ["Unpacking the zip", "Blocks path tricks, symlinks and zip bombs"],
  cloning: ["Cloning the repository", "Shallow https clone; nothing is executed"],
  scanning: ["Running the checks", "Personal data, code structure, missing safeguards, configuration"],
  "writing reports": ["Writing the reports", "JSON, HTML and SARIF, with evidence masked"],
  done: ["Report ready", "Opening the overview"],
};
const POLL_MS = 1000;

export function ScanProgress() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await getScanStatus(scanId);
        if (!live) return;
        setStatus(next);
        setError(null);
        if (next.status === "done") {
          rememberScope({ scanId, target: next.target });
          setExpiry(scanId, next.expires_at);
          timer = setTimeout(() => navigate(`/scans/${scanId}`, { replace: true }), 450);
          return;
        }
        if (next.status === "failed") return;
      } catch (e) {
        if (!live) return;
        const err = e instanceof ApiError ? e : new ApiError(0, String(e));
        setError(err);
        if (err.status === 404 || err.status === 410) return; // unknown, expired or not this tab's: polling again will not help
      }
      timer = setTimeout(poll, POLL_MS);
    };
    poll();
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [scanId, navigate]);

  const createdAt = status?.created_at;
  const running = status !== null && status.status !== "failed" && status.status !== "done";
  useEffect(() => {
    if (!createdAt || !running) return;
    const started = new Date(createdAt).getTime();
    const tick = () => setElapsed(Math.max(0, Math.round((Date.now() - started) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [createdAt, running]);

  const failed = status?.status === "failed";
  useEffect(() => {
    if (failed) heading.current?.focus();
  }, [failed]);

  const steps = status?.steps ?? [];
  const current = status ? steps.indexOf(status.step) : -1;
  const done = status?.status === "done";
  const percent = steps.length ? Math.round(((done ? steps.length - 1 : Math.max(current, 0)) / (steps.length - 1)) * 100) : 0;
  const title = failed ? "Scan failed" : done ? "Report ready" : "Scanning";

  return (
    <section className="page narrow arrive">
      <Heading
        eyebrow={status ? (status.source === "git" ? "Git repository" : "Zip upload") : "Scan"}
        title={<span className="breakall">{status?.target ?? "Starting scan…"}</span>}
      />
      <div className="panel progresspanel">
        <div className="between">
          <h2 className="type-pixel" ref={heading} tabIndex={-1}>
            {title}
          </h2>
          <b className="tabular" aria-hidden="true">
            {failed ? "—" : `${percent}%`}
          </b>
        </div>
        <div className={`track progress${failed ? " failed" : ""}`} role="progressbar" aria-label="Scan progress" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100}>
          <i style={{ transform: `scaleX(${failed ? 1 : percent / 100})` }} />
        </div>
        <ol className="stages" aria-live="polite">
          {status
            ? steps.map((step, i) => {
                const state = i < current || done ? "done" : i === current ? (failed ? "failed" : "active") : "todo";
                const [name, note] = STAGES[step] ?? [step, ""];
                return (
                  <li className={`stage ${state}`} key={step}>
                    {state === "done" ? (
                      <Check aria-hidden="true" />
                    ) : state === "active" ? (
                      <LoaderCircle className="spin" aria-hidden="true" />
                    ) : state === "failed" ? (
                      <X aria-hidden="true" />
                    ) : (
                      <Circle aria-hidden="true" />
                    )}
                    <div>
                      <strong className="type-pixel">{name}</strong>
                      <small>{note}</small>
                    </div>
                    <span className="sr-only">({{ done: "done", active: "in progress", failed: "failed", todo: "not started" }[state]})</span>
                  </li>
                );
              })
            : !error && (
                <li className="stage active">
                  <LoaderCircle className="spin" aria-hidden="true" />
                  <div>
                    <strong className="type-pixel">Contacting the scanner</strong>
                  </div>
                </li>
              )}
        </ol>
        {running && (
          <p className="tabular elapsed">
            {elapsed}s elapsed · large repositories can take a minute
          </p>
        )}
      </div>

      {failed && (
        <div className="stack-gap">
          <Notice kind="error" title={`The scan failed while ${STAGES[status.step]?.[0].toLowerCase() ?? status.step}`}>
            {status.error ?? "Unknown error"}
          </Notice>
        </div>
      )}
      {error && (
        <div className="stack-gap">
          <Notice kind="error" title={error.status === 404 || error.status === 410 ? "This scan has expired or was not found" : "Lost contact with the scanner"}>
            {error.status === 404 || error.status === 410
              ? "Scans are cleared when you reload or leave, and the server deletes them 30 minutes after they were created."
              : `${error.message} Retrying…`}
          </Notice>
        </div>
      )}
      {(failed || error?.status === 404 || error?.status === 410) && (
        <div className="formactions stack-gap">
          <Link className="btn mint" to="/scan">
            <ScanLine aria-hidden="true" />
            Start a new scan
          </Link>
          <Link className="textlink" to={`/scans/${SAMPLE_ID}`}>
            Open the saved sample report
          </Link>
        </div>
      )}
      <p className="footnote">The uploaded code is deleted as soon as the scan ends, whether it succeeds or fails.</p>
    </section>
  );
}
