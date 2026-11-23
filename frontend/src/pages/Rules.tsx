// Rule catalogue (/rules) from GET /api/rules: the 28 rules of rules/dpdp_rules.yml with
// their legal references, severity and whether a detector checks them automatically.

import { Search } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { ApiError, getCatalogue, type Catalogue } from "../api";
import { Heading, Notice, PageSkeleton, SeverityBadge } from "../components/ui";

export function Rules() {
  const [catalogue, setCatalogue] = useState<Catalogue | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [params, setParams] = useSearchParams();
  const query = params.get("q") ?? "";
  const category = params.get("cat") ?? "";
  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  };

  useEffect(() => {
    let live = true;
    getCatalogue().then(
      (c) => live && setCatalogue(c),
      (e: unknown) => live && setError(e instanceof ApiError ? e.message : String(e)),
    );
    return () => {
      live = false;
    };
  }, []);

  if (error)
    return (
      <section className="page narrow arrive">
        <Heading eyebrow="Rules" title="Rule catalogue" />
        <Notice kind="error" title="The catalogue is unavailable">
          {error}
        </Notice>
      </section>
    );
  if (!catalogue) return <PageSkeleton label="Loading the rule catalogue…" />;

  const checked = new Set(catalogue.checked);
  const categories = [...new Set(catalogue.rules.map((r) => r.category))];
  const q = query.trim().toLowerCase();
  const rules = catalogue.rules.filter(
    (r) =>
      (!category || r.category === category) &&
      (!q || [r.id, r.title, r.category, ...r.law.act, ...r.law.rules, ...r.detects].some((s) => s.toLowerCase().includes(q))),
  );

  return (
    <section className="page arrive">
      <Heading
        eyebrow="Rules"
        title="Rule catalogue"
        sub={`${catalogue.rules.length} rules from rules/dpdp_rules.yml, the single source of each finding's legal meaning. ${checked.size} have an automated check.`}
      />
      <div className="toolbar">
        <label className="search">
          <Search size={16} aria-hidden="true" />
          <input type="search" aria-label="Search rules" placeholder="Rule id, title, provision" value={query} onChange={(e) => set("q", e.target.value)} />
        </label>
        <select aria-label="Category" value={category} onChange={(e) => set("cat", e.target.value)}>
          <option value="">All categories</option>
          {categories.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <span className="tablemeta inline tabular" aria-live="polite">
          {rules.length} of {catalogue.rules.length}
        </span>
      </div>
      <div className="tablewrap rulestable">
        <table>
          <thead>
            <tr>
              <th scope="col">Rule</th>
              <th scope="col">Check</th>
              <th scope="col">Law</th>
              <th scope="col">Severity</th>
              <th scope="col">Automated</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr key={r.id} id={r.id}>
                <td className="mono ruleid">{r.id}</td>
                <td>
                  <span className="rowtitle">{r.title}</span>
                  <small>{r.category}</small>
                  <ul className="detects">
                    {r.detects.map((d) => (
                      <li key={d}>{d}</li>
                    ))}
                  </ul>
                </td>
                <td>
                  <span className="chips">
                    {[...r.law.act, ...r.law.rules].map((p) => (
                      <span key={p} className="chip law">
                        {p}
                      </span>
                    ))}
                  </span>
                </td>
                <td>
                  <SeverityBadge severity={r.severity} />
                </td>
                <td>{checked.has(r.id) ? <span className="yes">Yes</span> : <span className="muted">Manual</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rules.length && <p className="emptyrow">No rule matches.</p>}
      </div>
    </section>
  );
}
