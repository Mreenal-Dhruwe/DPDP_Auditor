// Screen 1: start a scan (zip upload or Git URL), then follow its progress.

import { useEffect, useRef, useState, type DragEvent, type FormEvent, type KeyboardEvent } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ApiError, getScanStatus, SAMPLE_ID, startGitScan, startZipScan } from "../api";
import { Card, ErrorBox } from "../components/States";
import type { ScanStatus } from "../types/contract";

const JUICE_SHOP = "https://github.com/juice-shop/juice-shop";

export function Upload() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [gitUrl, setGitUrl] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const chooseFile = (chosen: File | null) => {
    setError(null);
    if (chosen && !chosen.name.toLowerCase().endsWith(".zip")) {
      setError(`"${chosen.name}" is not a .zip file. Zip the project folder first.`);
      return;
    }
    setFile(chosen);
    if (chosen) setGitUrl("");
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const url = gitUrl.trim();
    if (!file && !url) return;
    setBusy(true);
    setError(null);
    try {
      const { scan_id } = file ? await startZipScan(file) : await startGitScan(url);
      navigate(`/scans/${scan_id}/progress`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
      setBusy(false);
    }
  };

  return (
    <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_320px]">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Scan an application</h1>
        <p className="mt-2 max-w-2xl text-ink-2">
          Upload the source code or point to a Git repository. Each finding is mapped to the DPDP Act, 2023 and the
          DPDP Rules, 2025, with the file and line, the severity and a fix.
        </p>

        <form onSubmit={submit} className="mt-6 space-y-5">
          <DropZone file={file} onFile={chooseFile} disabled={busy} />

          <div className="flex items-center gap-3 text-xs font-medium uppercase tracking-wide text-muted">
            <span className="h-px flex-1 bg-line" />
            or scan a Git repository
            <span className="h-px flex-1 bg-line" />
          </div>

          <div>
            <label htmlFor="git-url" className="text-sm font-medium">Repository URL</label>
            <input
              id="git-url"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              placeholder="https://github.com/owner/repository"
              value={gitUrl}
              disabled={busy}
              onChange={(e) => {
                setGitUrl(e.target.value);
                if (e.target.value) setFile(null);
                setError(null);
              }}
              className="mt-1.5 block w-full rounded-lg border border-line-strong bg-surface px-3 py-2.5 font-mono text-sm text-ink placeholder:text-muted focus:border-accent focus:outline-none disabled:opacity-60"
            />
            <p className="mt-1.5 text-xs text-muted">
              Public https repositories on GitHub, GitLab or Bitbucket.{" "}
              <button
                type="button"
                className="text-accent hover:underline disabled:opacity-60"
                disabled={busy}
                onClick={() => {
                  setGitUrl(JUICE_SHOP);
                  setFile(null);
                  setError(null);
                }}
              >
                Use OWASP Juice Shop
              </button>
            </p>
          </div>

          {error && <ErrorBox title="Could not start the scan">{error}</ErrorBox>}

          <div className="flex flex-wrap items-center gap-4">
            <button
              type="submit"
              disabled={busy || (!file && !gitUrl.trim())}
              className="inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-semibold text-on-accent transition-colors hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
            >
              {busy && <span className="size-3.5 animate-spin rounded-full border-2 border-current/40 border-t-current" aria-hidden="true" />}
              {busy ? "Starting…" : "Start scan"}
            </button>
            <Link to={`/scans/${SAMPLE_ID}`} className="text-sm text-accent hover:underline">
              Or open the sample report
            </Link>
          </div>
        </form>
      </div>

      <aside className="space-y-4">
        <Card title="How the scan works">
          <ol className="space-y-3 text-sm text-ink-2">
            <Step n={1} title="Read, never run">The code is parsed as text. Nothing you upload is executed.</Step>
            <Step n={2} title="Find personal data">Fields and values such as Aadhaar, PAN, phone and email, and where they flow.</Step>
            <Step n={3} title="Check the rules">Logs, storage, access, consent, retention, third parties, children and config.</Step>
            <Step n={4} title="Map to the law">Each finding cites the Act section, the Rule and the penalty cap.</Step>
          </ol>
        </Card>
        <p className="px-1 text-xs leading-relaxed text-muted">
          Uploads are unpacked safely (no path tricks, symlinks or zip bombs) and deleted as soon as the scan ends.
          Evidence in reports is masked.
        </p>
      </aside>
    </div>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: string }) {
  return (
    <li className="flex gap-3">
      <span className="tabular flex size-5 shrink-0 items-center justify-center rounded-full bg-accent-soft text-xs font-semibold text-accent">
        {n}
      </span>
      <span>
        <span className="font-medium text-ink">{title}.</span> {children}
      </span>
    </li>
  );
}

function DropZone({ file, onFile, disabled }: { file: File | null; onFile: (f: File | null) => void; disabled: boolean }) {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);

  const drop = (event: DragEvent) => {
    event.preventDefault();
    setOver(false);
    if (!disabled) onFile(event.dataTransfer.files[0] ?? null);
  };
  const keyOpen = (event: KeyboardEvent) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      input.current?.click();
    }
  };

  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      aria-label="Upload a zip of the project: drop it here or press Enter to choose a file"
      onClick={() => !disabled && input.current?.click()}
      onKeyDown={keyOpen}
      onDragOver={(e) => {
        e.preventDefault();
        setOver(true);
      }}
      onDragLeave={() => setOver(false)}
      onDrop={drop}
      className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-6 py-10 text-center transition-colors ${
        over ? "border-accent bg-accent-soft" : file ? "border-line-strong bg-surface" : "border-line-strong bg-surface hover:border-accent"
      } ${disabled ? "pointer-events-none opacity-60" : ""}`}
    >
      <input
        ref={input}
        type="file"
        accept=".zip,application/zip"
        className="hidden"
        data-testid="zip-input"
        onChange={(e) => {
          onFile(e.target.files?.[0] ?? null);
          e.target.value = "";
        }}
      />
      <ZipIcon />
      {file ? (
        <>
          <p className="mt-3 font-medium text-ink">{file.name}</p>
          <p className="tabular text-sm text-muted">{formatBytes(file.size)}</p>
          <button
            type="button"
            className="mt-2 text-sm text-accent hover:underline"
            onClick={(e) => {
              e.stopPropagation();
              onFile(null);
            }}
          >
            Remove
          </button>
        </>
      ) : (
        <>
          <p className="mt-3 font-medium text-ink">Drop a .zip of the project here</p>
          <p className="text-sm text-muted">or click to choose a file</p>
        </>
      )}
    </div>
  );
}

function ZipIcon() {
  return (
    <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-muted" aria-hidden="true">
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" strokeLinejoin="round" />
      <path d="M14 3v5h5" strokeLinejoin="round" />
      <path d="M10 6h1M10 9h1M10 12h1M9.5 15h2v3h-2z" strokeLinecap="round" />
    </svg>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

// --- progress ----------------------------------------------------------------------------

const STEP_TEXT: Record<string, string> = {
  queued: "Queued",
  unpacking: "Unpacking the zip safely",
  cloning: "Cloning the repository",
  scanning: "Finding personal data and running the checks",
  "writing reports": "Writing the JSON, HTML and SARIF reports",
  done: "Done",
};
const POLL_MS = 1000;

export function ScanProgress() {
  const { scanId = "" } = useParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [elapsed, setElapsed] = useState(0);

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
          navigate(`/scans/${scanId}`, { replace: true });
          return;
        }
        if (next.status === "failed") return;
      } catch (e) {
        if (!live) return;
        const err = e instanceof ApiError ? e : new ApiError(0, String(e));
        setError(err);
        if (err.status === 404) return; // unknown scan: polling again will not help
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
  const running = status !== null && status.status !== "failed";
  useEffect(() => {
    if (!createdAt || !running) return;
    const started = new Date(createdAt).getTime();
    const tick = () => setElapsed(Math.max(0, Math.round((Date.now() - started) / 1000)));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [createdAt, running]);

  const failed = status?.status === "failed";
  const current = status ? status.steps.indexOf(status.step) : -1; // on failure: the step that failed

  return (
    <div className="mx-auto max-w-xl">
      <p className="text-sm text-muted">{status ? (status.source === "git" ? "Git repository" : "Zip upload") : "Scan"}</p>
      <h1 className="mt-1 break-all text-2xl font-semibold tracking-tight">{status?.target ?? "Starting scan…"}</h1>

      <Card className="mt-6">
        {status ? (
          <ol className="space-y-1" aria-live="polite">
            {status.steps.map((step, i) => {
              const state: StepState =
                i < current || status.status === "done" ? "done" : i === current ? (failed ? "failed" : "active") : "todo";
              return <ProgressStep key={step} state={state} label={STEP_TEXT[step] ?? step} />;
            })}
          </ol>
        ) : (
          !error && <ProgressStep state="active" label="Contacting the scanner" />
        )}
        {status && !failed && (
          <p className="tabular mt-4 border-t border-line pt-3 text-xs text-muted">
            {elapsed}s elapsed · large repositories can take a minute
          </p>
        )}
      </Card>

      {failed && (
        <div className="mt-4">
          <ErrorBox title="The scan failed">{status.error ?? "Unknown error"}</ErrorBox>
        </div>
      )}
      {error && (
        <div className="mt-4">
          <ErrorBox title={error.status === 404 ? "Scan not found" : "Lost contact with the scanner"}>
            {error.status === 404
              ? "This scan id is unknown. Scans are kept in memory, so a server restart forgets them."
              : `${error.message} Retrying…`}
          </ErrorBox>
        </div>
      )}
      {(failed || error?.status === 404) && (
        <Link to="/" className="mt-4 inline-block text-sm font-medium text-accent hover:underline">
          Start a new scan
        </Link>
      )}
      <p className="mt-6 text-xs text-muted">The uploaded code is deleted as soon as the scan ends, whether it succeeds or fails.</p>
    </div>
  );
}

type StepState = "done" | "active" | "todo" | "failed";

function ProgressStep({ state, label }: { state: StepState; label: string }) {
  const marker = {
    done: (
      <svg viewBox="0 0 20 20" className="size-5 text-ok-ink" aria-hidden="true">
        <circle cx="10" cy="10" r="9" fill="currentColor" opacity=".14" />
        <path d="M6 10.5l2.7 2.7L14 7.8" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    ),
    active: <span className="size-5 animate-spin rounded-full border-2 border-line-strong border-t-accent" aria-hidden="true" />,
    todo: <span className="size-5 rounded-full border-2 border-line" aria-hidden="true" />,
    failed: (
      <svg viewBox="0 0 20 20" className="size-5 text-danger-ink" aria-hidden="true">
        <circle cx="10" cy="10" r="9" fill="currentColor" opacity=".14" />
        <path d="M7 7l6 6M13 7l-6 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      </svg>
    ),
  }[state];
  const words = { done: "done", active: "in progress", todo: "not started", failed: "failed" }[state];
  return (
    <li className="flex items-center gap-3 py-1.5">
      {marker}
      <span className={state === "todo" ? "text-muted" : state === "failed" ? "font-medium text-danger-ink" : state === "active" ? "font-medium text-ink" : "text-ink-2"}>
        {label}
      </span>
      <span className="sr-only">({words})</span>
    </li>
  );
}
