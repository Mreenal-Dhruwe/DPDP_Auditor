import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { motion } from "motion/react";
import {
  Search,
  Circle,
  CircleDashed,
  CircleDot,
  CircleCheck,
  X,
  FileCode2,
  Columns3,
  List,
  GripVertical,
  ShieldCheck,
} from "lucide-react";
import {
  report,
  statuses,
  levels,
  locationOf,
  provisions,
  type Status,
} from "./data";
import { Heading, Badge, Select, StatusSelect, useReviews, Miss } from "./ui";

export function Findings() {
  const location = useLocation();
  const [q, setQ] = useState(""),
    [severity, setSeverity] = useState("All severities"),
    [list, setList] = useState(false);
  const [drag, setDrag] = useState(""),
    [over, setOver] = useState<Status | null>(null),
    [message, setMessage] = useState("");
  const { reviews, move } = useReviews();
  const filtered = report.findings.filter(
    (f) =>
      (severity === "All severities" || f.severity === severity) &&
      [f.title, f.id, f.rule_id, f.file, f.category, provisions(f)]
        .join(" ")
        .toLowerCase()
        .includes(q.toLowerCase()),
  );
  function drop(status: Status) {
    if (drag) {
      move(drag, status);
      setMessage(drag + " moved to " + status);
    }
    setDrag("");
    setOver(null);
  }
  return (
    <section className="page">
      <Heading title="Findings" sub={report.repository + "  /  " + report.id}>
        <div className="tabs viewtabs">
          <button aria-pressed={!list} onClick={() => setList(false)}>
            <Columns3 />
            Board
          </button>
          <button aria-pressed={list} onClick={() => setList(true)}>
            <List />
            List
          </button>
        </div>
      </Heading>
      <div className="toolbar">
        <label className="search">
          <Search size={16} />
          <input
            aria-label="Search findings"
            placeholder="Search findings, files, rules…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <Select
          label="Filter severity"
          value={severity}
          items={["All severities", ...levels]}
          change={setSeverity}
        />
        <small>{filtered.length} findings</small>
      </div>
      <span aria-live="polite" className="sr-only">
        {message}
      </span>
      {list ? (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                {["Finding", "Severity", "Review status"].map((v) => (
                  <th key={v}>{v}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Link to={"/findings/" + f.id}>{f.title}</Link>
                    <small>{locationOf(f)}</small>
                  </td>
                  <td>
                    <Badge value={f.severity} />
                  </td>
                  <td>
                    <StatusSelect id={f.id} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filtered.length && <p>No matching findings.</p>}
        </div>
      ) : (
        <div className="board">
          {statuses.map((status, i) => {
            const cards = filtered.filter((f) => reviews[f.id] === status),
              Icon = [Circle, CircleDashed, CircleDot, CircleCheck][i];
            return (
              <section
                key={status}
                className={"column col" + i + (over === status ? " over" : "")}
                onDragOver={(e) => {
                  if (drag) {
                    e.preventDefault();
                    setOver(status);
                  }
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  drop(status);
                }}
              >
                <h2>
                  <Icon size={16} />
                  <span className="type-pixel">{status}</span>
                  <small>{cards.length}</small>
                </h2>
                <div className="stack">
                  {cards.map((f) => (
                    <motion.article
                      layout
                      layoutId={f.id}
                      transition={{ duration: 0.24 }}
                      draggable
                      onDragStartCapture={(e) => {
                        e.dataTransfer.setData("text/plain", f.id);
                        e.dataTransfer.effectAllowed = "move";
                        setDrag(f.id);
                      }}
                      onDragEndCapture={() => {
                        setDrag("");
                        setOver(null);
                      }}
                      className={
                        "finding-card " + (drag === f.id ? "dragging" : "")
                      }
                      key={f.id}
                    >
                      <div className="cardtop">
                        <span>{f.id}</span>
                        <GripVertical size={14} />
                      </div>
                      <Link
                        className="cardtitle"
                        draggable={false}
                        state={{ board: location }}
                        to={"/findings/" + f.id}
                      >
                        {f.title}
                      </Link>
                      <small>
                        <FileCode2 size={13} />
                        {locationOf(f)}
                      </small>
                      <div className="cardbottom">
                        <Badge value={f.severity} />
                        <StatusSelect id={f.id} />
                      </div>
                    </motion.article>
                  ))}
                  {!cards.length && (
                    <p className="empty">No matching findings</p>
                  )}
                  {drag && over === status && (
                    <div className="insert">Move to {status}</div>
                  )}
                </div>
              </section>
            );
          })}
        </div>
      )}
    </section>
  );
}
export function Details({ drawer = false }: { drawer?: boolean }) {
  const { id } = useParams(),
    f = report.findings.find((item) => item.id === id);
  if (!f) return <Miss />;
  return (
    <section className="page">
      {!drawer && (
        <Link className="textlink" to="/findings">
          Back to findings
        </Link>
      )}
      <Heading
        title={f.title}
        sub={f.id + "  /  " + f.rule_id + "  /  " + f.category}
      />
      <div className="detailgrid">
        <div>
          <div className="panel">
            <div className="between">
              <h2 className="type-pixel">Evidence</h2>
              <span className="chip">{f.scope} scope</span>
            </div>
            <p className="mono">{locationOf(f)}</p>
            <div className="code">
              {f.context ? (
                f.context.lines.map((line, i) => (
                  <div
                    key={i}
                    className={
                      f.context!.start_line + i === f.line ? "flagged" : ""
                    }
                  >
                    <span>{f.context!.start_line + i}</span>
                    <code>{line}</code>
                  </div>
                ))
              ) : (
                <pre>{f.evidence}</pre>
              )}
            </div>
            <small>Synthetic, masked evidence</small>
            <h3>Personal-data fields</h3>
            <div className="chips">
              {f.pii.map((p) => (
                <span key={p}>{p}</span>
              ))}
            </div>
          </div>
          <div className="panel">
            <h2>Review and remediation</h2>
            <h3>Severity rationale</h3>
            <p>{f.severity_reason}</p>
            <h3 className="type-pixel">Suggested fix</h3>
            <p>{f.fix}</p>
          </div>
        </div>
        <aside>
          <div className="panel metadata">
            <h2 className="type-pixel">Finding properties</h2>
            <div>
              Severity <Badge value={f.severity} />
            </div>
            <div>
              Detection confidence <b>{f.confidence}</b>
            </div>
            <div>
              Review status <StatusSelect id={f.id} />
            </div>
          </div>
          <div className="panel">
            <h2 className="type-pixel">
              <ShieldCheck size={18} /> Provision mapping
            </h2>
            <p className="accent">{provisions(f)}</p>
            <p>{f.law.requirement}</p>
            <small>Indicative statutory cap · {f.penalty}</small>
            <small>{report.disclaimer}</small>
          </div>
        </aside>
      </div>
    </section>
  );
}

export function EvidenceDrawer() {
  const ref = useRef<HTMLDialogElement>(null),
    navigate = useNavigate();
  useEffect(() => {
    const dialog = ref.current!;
    dialog.showModal();
    return () => dialog.close();
  }, []);
  return (
    <dialog
      ref={ref}
      className="drawer"
      aria-label="Finding evidence"
      onCancel={(e) => {
        e.preventDefault();
        navigate(-1);
      }}
      onClick={(e) => {
        if (
          e.target === ref.current &&
          e.clientX < ref.current.getBoundingClientRect().left
        )
          navigate(-1);
      }}
    >
      <div className="drawerbar">
        <span>Finding detail</span>
        <button aria-label="Close finding detail" onClick={() => navigate(-1)}>
          <X size={19} />
        </button>
      </div>
      <Details drawer />
    </dialog>
  );
}
