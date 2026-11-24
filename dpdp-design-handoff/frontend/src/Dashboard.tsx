import { useState } from "react";
import { Link } from "react-router-dom";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { useReducedMotion } from "motion/react";
import {
  Layers3,
  ShieldAlert,
  FileCode2,
  ListChecks,
  GitBranch,
} from "lucide-react";
import { report, countBy, levels, locationOf } from "./data";
import { Heading, Badge, Select } from "./ui";

export default function Dashboard() {
  const [category, setCategory] = useState("All categories");
  const findings = report.findings.filter(
    (f) => category === "All categories" || f.category === category,
  );
  const counts = countBy(findings, "severity"),
    reduced = useReducedMotion();
  const cats = Object.keys(countBy(report.findings, "category"));
  const chart = Object.entries(countBy(findings, "category")).map(
    ([name, count]) => ({
      name: name === "Third parties" ? "Processors" : name,
      count,
    }),
  );
  const cov = report.coverage,
    coverage = Math.round((cov.analyzed / cov.eligible) * 100);
  const split = levels.slice(0, 4).map((name) => ({
    name,
    high: findings.filter((f) => f.severity === name && f.confidence === "high")
      .length,
    review: findings.filter(
      (f) => f.severity === name && f.confidence !== "high",
    ).length,
  }));
  const max = Math.max(1, ...split.flatMap((s) => [s.high, s.review]));
  return (
    <section className="dashboard">
      <div className="page topdash">
        <Heading
          title="Audit overview"
          sub={"Sample report " + report.id + "  /  " + report.repository}
        >
          <Select
            label="Filter overview by category"
            value={category}
            items={["All categories", ...cats]}
            change={setCategory}
          />
        </Heading>
        <div className="dashgrid">
          <div className="chartarea">
            <h2 className="type-pixel">Finding breakdown</h2>
            <div className="legend">
              <span>
                <i />
                Needs confirmation
              </span>
              <span>
                <i />
                High confidence
              </span>
            </div>
            {split.map((s) => (
              <div className="compare" key={s.name}>
                <span>{s.name}</span>
                <div className="halves">
                  <div>
                    <b>{s.review}</b>
                    <i style={{ width: (s.review / max) * 70 + "%" }} />
                  </div>
                  <div>
                    <i style={{ width: (s.high / max) * 70 + "%" }} />
                    <b>{s.high}</b>
                  </div>
                </div>
              </div>
            ))}
            <h3 className="type-pixel">Findings by category</h3>
            <div
              className="bars"
              role="img"
              aria-label={chart.map((d) => d.name + " " + d.count).join(", ")}
            >
              <ResponsiveContainer width="100%" height="100%" minWidth={0}>
                <BarChart
                  data={chart}
                  margin={{ top: 4, right: 2, bottom: 0, left: -25 }}
                >
                  <CartesianGrid stroke="#26272c" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fill: "#b6b7c2", fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    interval={0}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#b6b7c2", fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: "#24252b" }}
                    contentStyle={{
                      background: "#19191d",
                      border: "1px solid #414148",
                    }}
                  />
                  <Bar
                    dataKey="count"
                    name="Findings"
                    fill="#b8a0ec"
                    maxBarSize={26}
                    isAnimationActive={!reduced}
                  />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div>
            <h2 className="type-pixel">Scan summary</h2>
            <div className="metrics">
              {[
                [Layers3, findings.length, "Findings in view"],
                [ShieldAlert, counts.critical ?? 0, "Critical findings"],
                [FileCode2, cov.analyzed, "Files analyzed · scan"],
                [ListChecks, cov.executed.length, "Rules checked · scan"],
              ].map(([Icon, value, label]) => {
                const I = Icon as typeof Layers3;
                return (
                  <div key={String(label)}>
                    <I size={19} />
                    <strong>{String(value)}</strong>
                    <span>{String(label)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
      <div className="lightband">
        <section>
          <h2 className="type-pixel">Scan coverage</h2>
          <strong>{coverage}%</strong>
          <p>
            {cov.analyzed} of {cov.eligible} files analyzed
          </p>
          <div className="track">
            <i style={{ width: coverage + "%" }} />
          </div>
          <small>{cov.excluded}</small>
        </section>
        <section>
          <h2 className="type-pixel">Project profile</h2>
          <p>
            <GitBranch size={15} /> {report.repository} / {report.branch}
          </p>
          <div className="chips">
            {cov.technologies.map((t) => (
              <span key={t}>{t}</span>
            ))}
          </div>
        </section>
        <section>
          <h2 className="type-pixel">Review queue</h2>
          <strong>
            {findings.filter((f) => f.confidence !== "high").length}
          </strong>
          <p>Findings to confirm against project context</p>
          <Link to="/findings">Open findings board</Link>
        </section>
      </div>
      <div className="page">
        <div className="between">
          <h2>Findings in scope</h2>
          <Link to="/reports" className="textlink">
            View report
          </Link>
        </div>
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                {["Finding", "Severity", "Affected location", "Confidence"].map(
                  (t) => (
                    <th key={t}>{t}</th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Link to={"/findings/" + f.id}>{f.title}</Link>
                  </td>
                  <td>
                    <Badge value={f.severity} />
                  </td>
                  <td className="mono">{locationOf(f)}</td>
                  <td>{f.confidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
