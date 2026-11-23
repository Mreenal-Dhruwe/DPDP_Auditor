import { useEffect, type CSSProperties } from "react";
import "./brand-intro.css";

const storageKey = "dpdp.brand-intro";
const motionPreference = "(prefers-reduced-motion: reduce)";
const duration = 2600;
let playedInMemory = false;

export function shouldPlayBrandIntro() {
  if (playedInMemory || matchMedia(motionPreference).matches) return false;
  try {
    return sessionStorage.getItem(storageKey) !== "played";
  } catch {
    return true;
  }
}

export default function BrandIntro({ dismiss }: { dismiss: () => void }) {
  useEffect(() => {
    playedInMemory = true;
    try {
      sessionStorage.setItem(storageKey, "played");
    } catch {
      // The in-memory flag also covers navigation with storage disabled.
    }

    function skip(event: KeyboardEvent) {
      if (event.key === "Escape") dismiss();
    }
    function stopScroll(event: WheelEvent) {
      event.preventDefault();
    }
    const reduced = matchMedia(motionPreference);
    function respectPreference() {
      if (reduced.matches) dismiss();
    }

    const fallback = window.setTimeout(dismiss, duration + 300);
    window.addEventListener("keydown", skip);
    window.addEventListener("wheel", stopScroll, { passive: false });
    reduced.addEventListener("change", respectPreference);
    respectPreference();
    return () => {
      window.clearTimeout(fallback);
      window.removeEventListener("keydown", skip);
      window.removeEventListener("wheel", stopScroll);
      reduced.removeEventListener("change", respectPreference);
    };
  }, [dismiss]);

  return (
    <div
      className="brand-intro"
      role="dialog"
      aria-modal="true"
      aria-label="DPDP Auditor introduction"
      style={{ "--intro-duration": duration + "ms" } as CSSProperties}
    >
      <div
        className="intro-shade"
        aria-hidden="true"
        onAnimationEnd={(event) => {
          if (event.animationName === "intro-aperture") dismiss();
        }}
      />
      <div className="intro-lockup" aria-hidden="true">
        <div className="intro-tile" />
        <img
          className="intro-mark"
          src="/mark.svg"
          alt=""
          width="48"
          height="48"
        />
        <div className="intro-wordmark">
          <strong>DPDP</strong> Auditor
        </div>
      </div>
      <button className="intro-skip" type="button" autoFocus onClick={dismiss}>
        Skip intro
      </button>
    </div>
  );
}
