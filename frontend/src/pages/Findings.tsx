// Findings workspace (/scans/:id/findings): review board and list. Cards move between
// review columns by drag and drop (pointer) or the status select on every card (keyboard,
// touch, screen readers). A move changes only the review map, never a scanner field.
// Opening a card shows the finding in a right-hand evidence drawer over the board; a direct
// link to /findings/:id renders the full page instead.

import { Circle, CircleCheck, CircleDashed, CircleDot, Columns3, FileCode2, GripVertical, List, Search, X } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useRef, useState, type DragEvent } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router";
import { ReviewSelect, useMoveWithUndo } from "../components/ReviewSelect";
import { ConfidenceMeter, Heading, SeverityBadge } from "../components/ui";
import { applyFilters, describeLocation, isFiltered, readFilters, SEVERITY_LABEL, writeFilters, type Filters } from "../lib/findings";
import { STATUSES, useReviews, type ReviewStatus } from "../lib/reviews";
import type { Finding } from "../types/contract";
import { CONFIDENCES, SEVERITIES } from "../types/contract";
import { FindingDetailPage, FindingView } from "./FindingDetail";
import { scanBase } from "../lib/paths";
import { useScan } from "./ScanLayout";

const COLUMN_ICON = { Open: Circle, Triaged: CircleDashed, "In progress": CircleDot, Resolved: CircleCheck } as const;
const COLUMN_HINT: Record<ReviewStatus, string> = {
  Open: "Not looked at yet",
  Triaged: "Confirmed, waiting for a fix",
  "In progress": "Being fixed",
  Resolved: "Fixed or accepted",
};

/** Board / list, plus the evidence drawer when a card was opened from the board. */
export function FindingsRoute() {
  const { findingId } = useParams();
  const location = useLocation();
  const fromBoard = Boolean((location.state as { board?: unknown } | null)?.board);
  if (findingId && !fromBoard) return <FindingDetailPage />;
  return (
    <>
      <Workspace />
      {findingId && <EvidenceDrawer findingId={findingId} />}
    </>
  );
}

function Workspace() {
  const { scanId, report } = useScan();
  const { statusOf, counts } = useReviews();
  const [params, setParams] = useSearchParams();
  const filters = readFilters(params);
  const view = params.get("view") === "list" ? "list" : "board";
  const update = (next: Filters, nextView = view) => {
    const p = writeFilters(next);
    if (nextView === "list") p.set("view", "list");
    setParams(p, { replace: true });
  };
  const shown = applyFilters(report.findings, filters);
  const resolved = counts.Resolved;

  return (
    <section className="page arrive workspacepage">
      <Heading
        eyebrow="Review workspace"
        title="Findings"
        sub={
          <>
            {report.target} · {report.summary.total} findings · <span className="tabular">{resolved}</span> resolved. Review status is cleared when you reload or leave;
            the scanner's severity, confidence and legal mapping never change.
          </>
        }
      >
        <div className="tabs" role="group" aria-label="View">
          <button type="button" aria-pressed={view === "board"} onClick={() => update(filters, "board")}>
            <Columns3 aria-hidden="true" /> Board
          </button>
          <button type="button" aria-pressed={view === "list"} onClick={() => update(filters, "list")}>
            <List aria-hidden="true" /> List
          </button>
        </div>
      </Heading>

      <div className="toolbar boardtools">
        <label className="search">
          <Search size={16} aria-hidden="true" />
          <input type="search" aria-label="Search findings" placeholder="Search titles, rules, paths, provisions" value={filters.query} onChange={(e) => update({ ...filters, query: e.target.value })} />
        </label>
        <div className="sevchips" role="group" aria-label="Severity">
          {SEVERITIES.map((s) => {
            const on = filters.severities.includes(s);
            return (
              <button
                key={s}
                type="button"
                aria-pressed={on}
                className={`sev-${s}`}
                onClick={() => update({ ...filters, severities: on ? filters.severities.filter((x) => x !== s) : [...filters.severities, s] })}
              >
                <i aria-hidden="true" />
                {SEVERITY_LABEL[s]}
              </button>
            );
          })}
        </div>
        <select aria-label="Confidence" value={filters.confidence} onChange={(e) => update({ ...filters, confidence: e.target.value as Filters["confidence"] })}>
          <option value="">Any confidence</option>
          {CONFIDENCES.map((c) => (
            <option key={c} value={c}>{`${c} confidence`}</option>
          ))}
        </select>
        <span className="tablemeta inline tabular" aria-live="polite">
          {shown.length} of {report.findings.length}
          {isFiltered(filters) && (
            <button type="button" className="textlink" onClick={() => update({ ...filters, severities: [], confidence: "", query: "" })}>
              Clear
            </button>
          )}
        </span>
      </div>

      {view === "board" ? <Board findings={shown} /> : <ListView findings={shown} statusOf={statusOf} scanId={scanId} />}
    </section>
  );
}

function Board({ findings }: { findings: Finding[] }) {
  const { statusOf } = useReviews();
  const moveWithUndo = useMoveWithUndo();
  const location = useLocation();
  const [dragging, setDragging] = useState<Finding | null>(null);
  const [over, setOver] = useState<ReviewStatus | null>(null);
  // set synchronously at dragstart: the first dragover can arrive before React re-renders
  const dragRef = useRef<Finding | null>(null);

  const drop = (status: ReviewStatus) => {
    const card = dragRef.current;
    if (card && statusOf(card.id) !== status) moveWithUndo(card.id, card.title, status);
    dragRef.current = null;
    setDragging(null);
    setOver(null);
  };

  return (
    <div className={`board${dragging ? " isdragging" : ""}`}>
      {STATUSES.map((status, i) => {
        const cards = findings.filter((f) => statusOf(f.id) === status);
        const Icon = COLUMN_ICON[status];
        const target = dragging !== null && over === status && statusOf(dragging.id) !== status;
        return (
          <section
            key={status}
            className={`column col${i}${target ? " over" : ""}`}
            aria-labelledby={`col-${i}`}
            onDragEnter={(e: DragEvent) => {
              if (!dragRef.current) return;
              e.preventDefault(); // the spec makes an element a drop target when dragenter is cancelled
              setOver(status);
            }}
            onDragOver={(e: DragEvent) => {
              if (!dragRef.current) return;
              e.preventDefault();
              e.dataTransfer.dropEffect = "move";
              if (over !== status) setOver(status);
            }}
            onDragLeave={(e: DragEvent) => {
              if (!(e.currentTarget as HTMLElement).contains(e.relatedTarget as Node)) setOver((o) => (o === status ? null : o));
            }}
            onDrop={(e: DragEvent) => {
              e.preventDefault();
              drop(status);
            }}
          >
            <h2 id={`col-${i}`}>
              <Icon aria-hidden="true" />
              <span className="type-pixel">{status}</span>
              <motion.small key={cards.length} initial={{ scale: 1.25, opacity: 0.6 }} animate={{ scale: 1, opacity: 1 }} className="tabular">
                {cards.length}
              </motion.small>
            </h2>
            <p className="colhint">{COLUMN_HINT[status]}</p>
            <div className="stack">
                {cards.map((f) => (
                  <motion.article
                    layout
                    layoutId={`card-${f.id}`}
                    key={f.id}
                    // the shared layoutId glides the card from its old column to the new one
                    transition={{ type: "spring", stiffness: 520, damping: 40 }}
                    className={`finding-card sev-${f.severity}${dragging?.id === f.id ? " dragging" : ""}`}
                    draggable
                    onDragStartCapture={(e: DragEvent) => {
                      e.dataTransfer.setData("text/plain", f.id);
                      e.dataTransfer.effectAllowed = "move";
                      dragRef.current = f;
                      setDragging(f);
                    }}
                    onDragEndCapture={() => {
                      dragRef.current = null;
                      setDragging(null);
                      setOver(null);
                    }}
                  >
                    <div className="cardtop">
                      <SeverityBadge severity={f.severity} />
                      <span className="mono">{f.rule_id}</span>
                      <GripVertical className="grip" aria-hidden="true" />
                    </div>
                    <Link className="cardtitle" draggable={false} state={{ board: location }} to={{ pathname: `${location.pathname.replace(/\/findings.*$/, "")}/findings/${f.id}`, search: location.search }}>
                      {f.title}
                    </Link>
                    <small className="cardloc mono">
                      <FileCode2 aria-hidden="true" />
                      {describeLocation(f)}
                    </small>
                    <div className="cardbottom">
                      <ConfidenceMeter confidence={f.confidence} />
                      <ReviewSelect id={f.id} title={f.title} compact />
                    </div>
                  </motion.article>
                ))}
              {target && (
                <div className="insert" aria-hidden="true">
                  Move to {status}
                </div>
              )}
              {!cards.length && !target && <p className="empty">{dragging ? "Drop here" : "No findings"}</p>}
            </div>
          </section>
        );
      })}
    </div>
  );
}

function ListView({ findings, statusOf, scanId }: { findings: Finding[]; statusOf: (id: string) => ReviewStatus; scanId: string }) {
  const location = useLocation();
  if (!findings.length) return <p className="emptyrow">No findings match these filters.</p>;
  return (
    <div className="tablewrap findings-table">
      <table>
        <thead>
          <tr>
            <th scope="col">Finding</th>
            <th scope="col">Severity</th>
            <th scope="col" className="wide">
              Confidence
            </th>
            <th scope="col">Review status</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id} data-status={statusOf(f.id)}>
              <td>
                <Link className="rowtitle" state={{ board: location }} to={{ pathname: `${scanBase(scanId)}/findings/${f.id}`, search: location.search }}>
                  {f.title}
                </Link>
                <small className="mono">{describeLocation(f)}</small>
              </td>
              <td>
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="wide">
                <ConfidenceMeter confidence={f.confidence} />
              </td>
              <td>
                <ReviewSelect id={f.id} title={f.title} compact />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Right-hand evidence drawer (native modal dialog): Escape, the close button, a click on
 *  the backdrop or browser Back return to the board, which keeps its filters. */
function EvidenceDrawer({ findingId }: { findingId: string }) {
  const { report } = useScan();
  const navigate = useNavigate();
  const ref = useRef<HTMLDialogElement>(null);
  const finding = report.findings.find((f) => f.id === findingId);
  // Opened by a push from the board (prev / next replace it), so one step back is the board.
  const close = () => navigate(-1);

  useEffect(() => {
    const dialog = ref.current!;
    if (!dialog.open) dialog.showModal();
    return () => dialog.close();
  }, []);
  useEffect(() => {
    ref.current?.scrollTo({ top: 0 });
  }, [findingId]);

  return (
    <dialog
      ref={ref}
      className="drawer"
      aria-label={finding ? `Finding: ${finding.title}` : "Finding"}
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
      onClick={(e) => {
        if (e.target === ref.current && e.clientX < ref.current.getBoundingClientRect().left) close();
      }}
    >
      <div className="drawerbar">
        <span className="eyebrow">Finding detail</span>
        <button type="button" className="icon-btn" aria-label="Close finding detail" onClick={close}>
          <X aria-hidden="true" />
        </button>
      </div>
      <div className="drawerbody">
        {finding ? <FindingView finding={finding} inDrawer /> : <p className="emptyrow">This report has no finding with id {findingId}.</p>}
      </div>
    </dialog>
  );
}
