import { useEffect, useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  UploadCloud,
  GitBranch,
  FileArchive,
  Check,
  LoaderCircle,
  Circle,
  ScanLine,
} from "lucide-react";
import { Heading } from "./ui";
import { report } from "./data";

const stages = [
  "Repository ingestion",
  "Project profiling",
  "Personal-data identification",
  "Code and configuration analysis",
  "Rule evaluation",
  "Report generation",
];
const stageNotes = [
  "Prepare the selected source",
  "Identify languages and frameworks",
  "Inventory personal-data fields",
  "Review code and configuration signals",
  "Map evidence to DPDP provisions",
  "Assemble the masked sample report",
];
export function Scan() {
  const [method, setMethod] = useState("ZIP archive"),
    [file, setFile] = useState<File | null>(null),
    [url, setUrl] = useState(""),
    [error, setError] = useState(""),
    [drag, setDrag] = useState(false);
  const navigate = useNavigate();
  function accept(f?: File) {
    setError("");
    if (!f || !f.name.toLowerCase().endsWith(".zip") || !f.size) {
      setFile(null);
      setError("Select a non-empty .zip archive.");
    } else setFile(f);
  }
  function submit(e: FormEvent) {
    e.preventDefault();
    let source = file?.name;
    if (method === "Git URL") {
      try {
        const u = new URL(url.trim());
        if (
          u.protocol !== "https:" ||
          u.pathname.split("/").filter(Boolean).length < 2 ||
          u.username ||
          u.password ||
          u.search ||
          u.hash
        )
          throw Error();
        source = u.hostname + u.pathname;
      } catch {
        setError(
          "Enter an HTTPS repository URL with an owner and repository name.",
        );
        return;
      }
    } else if (!file) {
      setError("Choose a ZIP archive to continue.");
      return;
    }
    navigate("/scan/progress", { state: { source, start: Date.now() } });
  }
  return (
    <section className="page">
      <Heading
        title="New scan"
        sub="Choose a repository for a simulated privacy review."
      />
      <div className="scan-grid">
        <form className="panel scanform" onSubmit={submit}>
          <h2 className="type-pixel">Repository source</h2>
          <div className="tabs">
            {["ZIP archive", "Git URL"].map((m, i) => (
              <button
                type="button"
                aria-pressed={method === m}
                key={m}
                onClick={() => {
                  setMethod(m);
                  setError("");
                }}
              >
                {i ? <GitBranch /> : <FileArchive />}
                {m}
              </button>
            ))}
          </div>
          {method === "ZIP archive" ? (
            <label
              className={"dropzone " + (drag ? "over" : "")}
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDrag(false);
                accept(e.dataTransfer.files[0]);
              }}
            >
              <input
                type="file"
                accept=".zip"
                aria-label="Choose ZIP archive"
                onChange={(e) => accept(e.target.files?.[0])}
              />
              <UploadCloud size={34} />
              <strong>{file?.name || "Drop your ZIP archive here"}</strong>
              <span>
                {file ? "Choose a different file" : "or browse files"}
              </span>
            </label>
          ) : (
            <label className="field">
              Repository URL
              <input
                type="text"
                value={url}
                placeholder="https://github.com/owner/repository"
                onChange={(e) => {
                  setUrl(e.target.value);
                  setError("");
                }}
              />
            </label>
          )}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <p className="subtle">
            Files stay on your device. Both input methods open the same sample
            report.
          </p>
          <button className="btn mint">
            <ScanLine size={16} />
            Start scan
          </button>
        </form>
        <aside className="scaninfo">
          <h2 className="type-pixel">Simulation stages</h2>
          {stages.map((s, i) => (
            <div key={s}>
              <span>{String(i + 1).padStart(2, "0")}</span>
              {s}
            </div>
          ))}
          <small>Sample repository · {report.repository}</small>
        </aside>
      </div>
    </section>
  );
}
export function Progress() {
  const { state } = useLocation(),
    navigate = useNavigate(),
    [now, setNow] = useState(Date.now);
  const valid =
    typeof state?.source === "string" && Number.isFinite(state?.start);
  const step = valid
    ? Math.min(
        stages.length,
        Math.max(0, Math.floor((now - state.start) / 900)),
      )
    : 0;
  useEffect(() => {
    if (!valid) return;
    const timer = setInterval(() => setNow(Date.now()), 150);
    return () => clearInterval(timer);
  }, [valid]);
  useEffect(() => {
    if (step === stages.length) {
      const timer = setTimeout(
        () => navigate("/dashboard", { replace: true }),
        850,
      );
      return () => clearTimeout(timer);
    }
  }, [step, navigate]);
  return (
    <section className="page narrow">
      <Heading
        title={valid ? "Scan progress" : "No active simulation"}
        sub={
          valid
            ? "Demo simulation · " + state.source
            : "Choose a repository to begin the six-stage demo."
        }
      />
      {valid ? (
        <div className="panel">
          <div className="between">
            <h2 className="type-pixel">
              {step === 6 ? "Sample report ready" : "Simulating scan"}
            </h2>
            <b>{Math.round((step / 6) * 100)}%</b>
          </div>
          <progress value={step} max={6} aria-label="Simulated scan progress" />
          <div aria-live="polite" className="sr-only">
            {stages[step] || "Report ready"}
          </div>
          {stages.map((s, i) => (
            <div className={"stage " + (i <= step ? "current" : "")} key={s}>
              {i < step ? (
                <Check />
              ) : i === step ? (
                <LoaderCircle className="spin" />
              ) : (
                <Circle />
              )}
              <div>
                <strong className="type-pixel">{s}</strong>
                <small>{stageNotes[i]}</small>
              </div>
            </div>
          ))}
          <Link to="/scan" className="textlink">
            Cancel simulation
          </Link>
        </div>
      ) : (
        <Link className="btn mint" to="/scan">
          New scan
        </Link>
      )}
    </section>
  );
}
