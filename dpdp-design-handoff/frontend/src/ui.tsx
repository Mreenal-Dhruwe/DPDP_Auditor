import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import {
  ChevronRight,
  BookOpen,
  FileChartColumn,
  LayoutDashboard,
  Columns3,
  ScanLine,
  Layers3,
} from "lucide-react";
import { report, statuses, type Status } from "./data";

type Reviews = Record<string, Status>;
const key = "dpdp.review." + report.id;
const initial = Object.fromEntries(
  report.findings.map((f, i) => [f.id, statuses[i % 4]]),
);
const Review = createContext({
  reviews: initial as Reviews,
  move: (_id: string, _status: Status) => {},
});
export function ReviewProvider({ children }: { children: ReactNode }) {
  const [reviews, setReviews] = useState<Reviews>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(key) || "{}");
      return Object.fromEntries(
        Object.entries(initial).map(([id, s]) => [
          id,
          statuses.includes(saved?.[id]) ? saved[id] : s,
        ]),
      );
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(reviews));
    } catch {
      /* In-memory review stays available. */
    }
  }, [reviews]);
  return (
    <Review.Provider
      value={{
        reviews,
        move: (id, status) => setReviews((old) => ({ ...old, [id]: status })),
      }}
    >
      {children}
    </Review.Provider>
  );
}
export const useReviews = () => useContext(Review);
export const Badge = ({ value }: { value: string }) => (
  <span className={"badge " + value}>
    <i />
    {value}
  </span>
);
export function Select({
  label,
  value,
  items,
  change,
}: {
  label: string;
  value: string;
  items: readonly string[];
  change: (v: string) => void;
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => change(e.target.value)}
    >
      {items.map((i) => (
        <option key={i}>{i}</option>
      ))}
    </select>
  );
}
export function StatusSelect({ id }: { id: string }) {
  const { reviews, move } = useReviews();
  return (
    <Select
      label={"Review status for " + id}
      value={reviews[id]}
      items={statuses}
      change={(v) => move(id, v as Status)}
    />
  );
}
const nav = [
  ["/dashboard", "Overview", LayoutDashboard],
  ["/scan", "New scan", ScanLine],
  ["/findings", "Findings", Columns3],
  ["/reports", "Reports", FileChartColumn],
  ["/rules", "Rule catalogue", BookOpen],
] as const;
export function Shell() {
  const { pathname } = useLocation();
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);
  return (
    <div className="workspace">
      <a className="skip" href="#content">
        Skip navigation
      </a>
      <aside className="rail">
        <Link to="/" aria-label="DPDP Auditor home">
          <img src="/mark.svg" alt="" />
        </Link>
        <nav aria-label="Workspace navigation">
          {nav.map(([path, label, I]) => (
            <NavLink key={path} to={path} aria-label={label}>
              <I size={20} aria-hidden="true" />
              <span aria-hidden="true">{label}</span>
            </NavLink>
          ))}
        </nav>
        <Layers3 className="railfoot" size={21} aria-hidden="true" />
      </aside>
      <main id="content">
        <div className="crumb">
          <span>DPDP Auditor</span>
          <ChevronRight size={13} />
          {nav.find(([p]) => pathname.startsWith(p))?.[1] || "Workspace"}
          <span className="demo">Demo workspace</span>
        </div>
        <Outlet />
      </main>
    </div>
  );
}
export function Heading({
  title,
  sub,
  children,
}: {
  title: string;
  sub?: string;
  children?: ReactNode;
}) {
  return (
    <header className="heading">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {children}
    </header>
  );
}
export function Miss() {
  return (
    <section className="page">
      <Heading
        title="Page unavailable"
        sub="This address has no matching view in the sample workspace."
      />
      <Link className="btn mint" to="/dashboard">
        Return to overview
      </Link>
    </section>
  );
}
