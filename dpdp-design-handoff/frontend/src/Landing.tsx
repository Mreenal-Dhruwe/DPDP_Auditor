import { Link } from "react-router-dom";
import {
  GitFork,
  Fingerprint,
  Workflow,
  Layers3,
  FileCode2,
  FileChartColumn,
  Menu,
  Pause,
  Play,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "motion/react";
import Aurora from "./Aurora";
import BrandIntro, { shouldPlayBrandIntro } from "./BrandIntro";
import { report } from "./data";
import "./landing-motion.css";

export function Brand() {
  return (
    <Link className="brand" to="/" aria-label="DPDP Auditor home">
      <img src="/mark.svg" alt="" />
      <b>
        DPDP<span> Auditor</span>
      </b>
    </Link>
  );
}

const capabilities = [
  [GitFork, "Git ingestion"],
  [FileCode2, "Code analysis"],
  [Fingerprint, "PII discovery"],
  [Workflow, "Data flows"],
  [Layers3, "Rule mapping"],
  [FileChartColumn, "Reports"],
] as const;

const destinations = [
  ["/dashboard", "Overview"],
  ["/findings", "Findings"],
  ["/reports", "Reports"],
] as const;

function ProductNav({
  expanded,
  close,
}: {
  expanded: boolean;
  close: () => void;
}) {
  const nav = useRef<HTMLElement>(null);
  const [hovered, setHovered] = useState<HTMLAnchorElement | null>(null);
  const [focused, setFocused] = useState<HTMLAnchorElement | null>(null);
  const [capsule, setCapsule] = useState({ x: 0, y: 0, width: 0, height: 0 });
  const active = hovered ?? focused;
  const [reduced, setReduced] = useState(
    () => matchMedia("(prefers-reduced-motion: reduce)").matches,
  );
  const revealed = Boolean(active && capsule.width);

  useEffect(() => {
    const preference = matchMedia("(prefers-reduced-motion: reduce)");
    function update() {
      setReduced(preference.matches);
    }
    preference.addEventListener("change", update);
    return () => preference.removeEventListener("change", update);
  }, []);

  useEffect(() => {
    if (!active) return;
    function measure() {
      const link = active!;
      if (link.offsetWidth) {
        setCapsule({
          x: link.offsetLeft - 7,
          y: link.offsetTop - 8,
          width: link.offsetWidth + 14,
          height: link.offsetHeight + 16,
        });
      }
    }
    measure();
    const observer = new ResizeObserver(measure);
    if (nav.current) observer.observe(nav.current);
    return () => observer.disconnect();
  }, [active]);

  return (
    <nav
      ref={nav}
      className={expanded ? "shown" : ""}
      aria-label="Product"
      onPointerOver={(event) => {
        if (event.pointerType !== "mouse") return;
        const link = (event.target as HTMLElement).closest("a");
        if (link) setHovered(link);
      }}
      onPointerLeave={() => setHovered(null)}
      onFocus={(event) => {
        if (
          event.target instanceof HTMLAnchorElement &&
          event.target.matches(":focus-visible")
        ) {
          setFocused(event.target);
        }
      }}
      onBlur={() => setFocused(null)}
    >
      <motion.span
        aria-hidden="true"
        className="nav-glass"
        initial={false}
        animate={{ ...capsule, opacity: revealed ? 1 : 0 }}
        transition={
          reduced
            ? { duration: 0 }
            : {
                type: "spring",
                stiffness: 410,
                damping: 34,
                opacity: { duration: 0.16 },
              }
        }
      />
      <a href="#platform" onClick={close}>
        Platform
      </a>
      {destinations.map(([path, label]) => (
        <Link key={path} to={path}>
          {label}
        </Link>
      ))}
    </nav>
  );
}

function CapabilityStrip({
  paused,
  toggle,
}: {
  paused: boolean;
  toggle: () => void;
}) {
  const Icon = paused ? Play : Pause;
  return (
    <section
      className="platform"
      id="platform"
      aria-labelledby="capability-caption"
    >
      <div className="capability-heading">
        <p id="capability-caption" className="type-pixel">
          From repository to compliance report
        </p>
        <button
          type="button"
          className="motion-toggle"
          aria-label={
            paused ? "Resume landing animations" : "Pause landing animations"
          }
          title={paused ? "Resume animations" : "Pause animations"}
          onClick={toggle}
        >
          <Icon size={15} aria-hidden="true" />
        </button>
      </div>
      <div className="capability-window">
        <div className="capability-track">
          {[false, true].map((copy) => (
            <ul
              className="capability-set"
              key={String(copy)}
              aria-hidden={copy || undefined}
            >
              {capabilities.map(([CapabilityIcon, label]) => (
                <li key={label}>
                  <CapabilityIcon aria-hidden="true" />
                  {label}
                </li>
              ))}
            </ul>
          ))}
        </div>
      </div>
    </section>
  );
}

export default function Landing() {
  const [menu, setMenu] = useState(false);
  const [paused, setPaused] = useState(false);
  const [intro, setIntro] = useState(shouldPlayBrandIntro);
  const landing = useRef<HTMLElement>(null);
  const hero = useRef<HTMLElement>(null);
  const returnFocus = useRef(false);
  const dismissIntro = useCallback(() => {
    returnFocus.current =
      document.activeElement?.classList.contains("intro-skip") ?? false;
    setIntro(false);
  }, []);

  useEffect(() => {
    if (!intro && returnFocus.current) {
      landing.current?.focus({ preventScroll: true });
      returnFocus.current = false;
    }
  }, [intro]);

  return (
    <>
      <main
        ref={landing}
        tabIndex={-1}
        className="landing"
        inert={intro}
        data-motion-paused={paused}
      >
        <header className="floatnav">
          <Brand />
          <ProductNav expanded={menu} close={() => setMenu(false)} />
          <div className="navend">
            <Link className="btn light small" to="/dashboard">
              Open workspace
            </Link>
            <button
              className="menu"
              onClick={() => setMenu(!menu)}
              aria-label="Toggle navigation"
              aria-expanded={menu}
            >
              {menu ? <X /> : <Menu />}
            </button>
          </div>
        </header>
        <section className="hero" ref={hero}>
          <h1 className="sr-only">Audit your data flows.</h1>
          <div className="hero-art">
            <Aurora hero={hero} paused={paused} />
          </div>
          <div className="hero-copy">
            <p>
              Trace personal data through your codebase. Review privacy risks
              and map findings to India’s DPDP framework.
            </p>
            <div className="actions">
              <Link className="btn mint" to="/scan">
                Start a scan
              </Link>
              <Link className="btn light" to="/dashboard">
                View demo
              </Link>
            </div>
          </div>
        </section>
        <CapabilityStrip
          paused={paused}
          toggle={() => setPaused((current) => !current)}
        />
        <section className="pastel" aria-label="Sample report statistics">
          {[
            [report.findings.length, "Sample findings"],
            [report.coverage.executed.length, "Rules checked in demo"],
            [
              new Set(report.findings.map((f) => f.scope)).size,
              "Evidence scopes",
            ],
          ].map(([v, l]) => (
            <div key={l}>
              <strong>{v}</strong>
              <span>{l}</span>
            </div>
          ))}
        </section>
        <footer className="landfoot">
          <span>DPDP Auditor</span>
          <span>Hackasol 5.0 · Prototype workspace</span>
        </footer>
      </main>
      {intro && <BrandIntro dismiss={dismissIntro} />}
    </>
  );
}
