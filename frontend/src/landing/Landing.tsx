// Landing page (/): floating glass navigation, the Aurora hero (three-line clipped headline,
// strand pulses, parallax), right-hand copy and actions, the capability marquee and the
// pastel facts panel. The brand intro plays here only, once per session, and is skippable.

import { FileChartColumn, FileCode2, Fingerprint, GitFork, Layers3, Menu, Pause, Play, ShieldCheck, X } from "lucide-react";
import { motion } from "motion/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { SAMPLE_ID } from "../api";
import { useLastScope } from "../lib/scope";
import { DISCLAIMER } from "../types/contract";
import Aurora from "./Aurora";
import BrandIntro, { shouldPlayBrandIntro } from "./BrandIntro";
import "./landing.css";

export function Brand() {
  return (
    <Link className="brand" to="/" aria-label="DPDP Auditor home">
      <img src="/mark.svg" alt="" width="29" height="29" />
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
  [ShieldCheck, "Consent checks"],
  [Layers3, "Rule mapping"],
  [FileChartColumn, "SARIF reports"],
] as const;

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(() => matchMedia("(prefers-reduced-motion: reduce)").matches);
  useEffect(() => {
    const query = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(query.matches);
    query.addEventListener("change", update);
    return () => query.removeEventListener("change", update);
  }, []);
  return reduced;
}

function ProductNav({ expanded, close, scanId }: { expanded: boolean; close: () => void; scanId: string }) {
  const nav = useRef<HTMLElement>(null);
  const [hovered, setHovered] = useState<HTMLAnchorElement | null>(null);
  const [focused, setFocused] = useState<HTMLAnchorElement | null>(null);
  const [capsule, setCapsule] = useState({ x: 0, y: 0, width: 0, height: 0 });
  const active = hovered ?? focused;
  const reduced = usePrefersReducedMotion();
  const revealed = Boolean(active && capsule.width);

  useEffect(() => {
    if (!active) return;
    const measure = () => {
      if (active.offsetWidth)
        setCapsule({ x: active.offsetLeft - 7, y: active.offsetTop - 8, width: active.offsetWidth + 14, height: active.offsetHeight + 16 });
    };
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
        if (event.target instanceof HTMLAnchorElement && event.target.matches(":focus-visible")) setFocused(event.target);
      }}
      onBlur={() => setFocused(null)}
    >
      <motion.span
        aria-hidden="true"
        className="nav-glass"
        initial={false}
        animate={{ ...capsule, opacity: revealed ? 1 : 0 }}
        transition={reduced ? { duration: 0 } : { type: "spring", stiffness: 410, damping: 34, opacity: { duration: 0.16 } }}
      />
      <a href="#platform" onClick={close}>
        Platform
      </a>
      <Link to={`/scans/${scanId}`}>Overview</Link>
      <Link to={`/scans/${scanId}/findings`}>Findings</Link>
      <Link to="/rules">Rules</Link>
    </nav>
  );
}

function CapabilityStrip({ paused, toggle }: { paused: boolean; toggle: () => void }) {
  const Icon = paused ? Play : Pause;
  return (
    <section className="platform" id="platform" aria-labelledby="capability-caption">
      <div className="capability-heading">
        <p id="capability-caption" className="type-pixel">
          From repository to compliance report
        </p>
        <button
          type="button"
          className="motion-toggle"
          aria-label={paused ? "Resume landing animations" : "Pause landing animations"}
          aria-pressed={paused}
          title={paused ? "Resume animations" : "Pause animations"}
          onClick={toggle}
        >
          <Icon size={15} aria-hidden="true" />
        </button>
      </div>
      <div className="capability-window">
        <div className="capability-track">
          {[false, true].map((copy) => (
            <ul className="capability-set" key={String(copy)} aria-hidden={copy || undefined}>
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

export function Landing() {
  const [menu, setMenu] = useState(false);
  const [paused, setPaused] = useState(false);
  const [intro, setIntro] = useState(shouldPlayBrandIntro);
  const landing = useRef<HTMLElement>(null);
  const hero = useRef<HTMLElement>(null);
  const returnFocus = useRef(false);
  const last = useLastScope();
  const scanId = last?.scanId ?? SAMPLE_ID;

  const dismissIntro = useCallback(() => {
    returnFocus.current = document.activeElement?.classList.contains("intro-skip") ?? false;
    setIntro(false);
  }, []);

  useEffect(() => {
    if (!intro && returnFocus.current) {
      landing.current?.focus({ preventScroll: true });
      returnFocus.current = false;
    }
  }, [intro]);

  useEffect(() => {
    document.title = "DPDP Auditor · Audit your data flows";
    return () => {
      document.title = "DPDP Compliance Auditor";
    };
  }, []);

  return (
    <>
      <main ref={landing} tabIndex={-1} className="landing" inert={intro} data-motion-paused={paused}>
        <header className="floatnav">
          <Brand />
          <ProductNav expanded={menu} close={() => setMenu(false)} scanId={scanId} />
          <div className="navend">
            <Link className="btn light small" to={last ? `/scans/${last.scanId}` : "/scan"}>
              Open workspace
            </Link>
            <button className="menu icon-btn" type="button" onClick={() => setMenu(!menu)} aria-label="Toggle navigation" aria-expanded={menu}>
              {menu ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}
            </button>
          </div>
        </header>
        <section className="hero" ref={hero}>
          <h1 className="sr-only">Audit your data flows.</h1>
          <div className="hero-art">
            <Aurora hero={hero} paused={paused} />
          </div>
          <div className="hero-copy">
            <p>Trace personal data through your codebase. Review privacy risks and map findings to India’s DPDP framework.</p>
            <div className="actions">
              <Link className="btn mint" to="/scan">
                Start a scan
              </Link>
              <Link className="btn light" to={`/scans/${SAMPLE_ID}`}>
                View sample
              </Link>
            </div>
          </div>
        </section>
        <CapabilityStrip paused={paused} toggle={() => setPaused((current) => !current)} />
        <section className="pastel" aria-label="What every scan covers">
          {[
            ["28", "DPDP rules checked on every scan"],
            ["3", "Evidence scopes: line, file, project"],
            ["0", "Lines of your code executed"],
          ].map(([value, label]) => (
            <div key={label}>
              <strong>{value}</strong>
              <span>{label}</span>
            </div>
          ))}
        </section>
        <footer className="landfoot">
          <span>DPDP Auditor · Hackasol 5.0</span>
          <span>{DISCLAIMER}</span>
        </footer>
      </main>
      {intro && <BrandIntro dismiss={dismissIntro} />}
    </>
  );
}
