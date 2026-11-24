import { useEffect, useId, useRef, type RefObject } from "react";

const sweep =
  "M254 -75 C264 8 337 51 375 106 C422 176 341 175 414 218 C476 252 520 172 583 254 C620 305 647 343 719 335 C807 324 780 403 711 408 C631 411 621 396 560 445 C493 499 439 529 388 470 C348 422 345 392 283 381 C210 372 173 450 116 456 C75 471 45 441 85 401 C117 369 176 347 204 305 C218 279 167 255 202 226 C247 189 245 189 230 162 C206 118 291 153 320 138 C368 111 252 44 196 -45 Z";
const silk =
  "M194 -32 L307 -24 C348 14 372 66 369 126 C350 83 335 88 304 63 C248 26 221 48 194 -32Z";
const folds =
  "M414 218 C476 252 520 172 583 254 C530 226 523 204 488 223 C457 241 436 229 414 218Z M388 470 C439 529 493 499 560 445 C498 470 488 523 444 502 C416 487 414 477 388 470Z";
const strands = [
  { path: sweep, offset: 0.1, light: 220, strength: 1 },
  {
    path: "M-50 496 C76 448 141 347 227 374 C310 397 230 506 175 478 C115 445 214 380 227 415 C245 463 172 482 189 435",
    offset: 0.53,
    light: 155,
    strength: 0.85,
  },
  {
    path: "M926 -26 C921 12 954 73 903 95 C814 132 851 221 910 218 C972 214 969 122 1036 120 C1102 119 1131 178 1123 231 C1115 285 1144 326 1228 329",
    offset: 0.32,
    light: 0,
    strength: 0.55,
  },
  {
    path: "M523 -19 C479 49 542 112 593 116 C670 123 643 37 613 -17",
    offset: 0.72,
    light: 0,
    strength: 0.46,
  },
  {
    path: "M710 408 C790 395 735 329 794 284 C843 241 783 193 757 235 C731 276 774 289 740 322",
    offset: 0.86,
    light: 175,
    strength: 0.74,
  },
];
const loopMs = 10_400;
const clamp = (value: number) => Math.max(0, Math.min(1, value));

function useAuroraMotion(
  svg: RefObject<SVGSVGElement | null>,
  hero: RefObject<HTMLElement | null>,
  paused: boolean,
) {
  const elapsed = useRef(0);
  const pausedRef = useRef(paused);
  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    const art = svg.current!;
    const section = hero.current!;
    const outlines = art.querySelector<SVGGElement>(".aurora-strands")!;
    const ribbons = art.querySelector<SVGGElement>(".aurora-ribbons")!;
    const reduced = matchMedia("(prefers-reduced-motion: reduce)");
    const pointer = matchMedia("(any-hover: hover) and (any-pointer: fine)");
    const paints = art.querySelectorAll<SVGRadialGradientElement>(".pulse-paint");
    const washes = art.querySelectorAll<SVGRadialGradientElement>(".headline-paint");
    const pulses = Array.from(
      art.querySelectorAll<SVGGElement>(".aurora-pulse"),
    ).map((group, index) => {
      const path = group.querySelector<SVGPathElement>("path")!;
      const length = path.getTotalLength();
      const paint = paints[index];
      paint.setAttribute("r", String(Math.min(76, length * 0.061)));
      return {
        group,
        path,
        length,
        paint,
        wash: washes[index],
      };
    });

    let targetX = 0,
      targetY = 0;
    let x = 0,
      y = 0;
    let unitsPerPixel = 1;
    let lastTime = 0;
    let frame = 0;

    function measure() {
      unitsPerPixel = 1200 / Math.max(1, art.getBoundingClientRect().width);
    }
    function center() {
      targetX = targetY = 0;
    }
    function follow(event: PointerEvent) {
      if (
        event.pointerType !== "mouse" ||
        !pointer.matches ||
        reduced.matches ||
        pausedRef.current
      )
        return;
      const bounds = section.getBoundingClientRect();
      targetX = clamp((event.clientX - bounds.left) / bounds.width) * 2 - 1;
      targetY = clamp((event.clientY - bounds.top) / bounds.height) * 2 - 1;
    }
    function tick(time: number) {
      frame = requestAnimationFrame(tick);
      const dt = lastTime ? Math.min(time - lastTime, 32) : 0;
      lastTime = time;
      if (pausedRef.current) {
        center();
        if (Math.abs(x) + Math.abs(y) < 0.001) return;
      } else {
        elapsed.current = (elapsed.current + dt) % loopMs;
      }

      const ease = 1 - Math.exp(-dt / 145);
      x += (targetX - x) * ease;
      y += (targetY - y) * ease;
      const tx = x * unitsPerPixel,
        ty = y * unitsPerPixel;
      outlines.setAttribute("transform", `translate(${tx * 6} ${ty * 4})`);
      ribbons.setAttribute("transform", `translate(${tx * 11} ${ty * 7})`);

      const progress = elapsed.current / loopMs;
      pulses.forEach(({ group, path, length, paint, wash }, index) => {
        const strand = strands[index];
        const phase = (progress + strand.offset) % 1;
        const point = path.getPointAtLength(phase * length);
        // Fade at the path ends and near the navigation and copy.
        const ends = Math.min(clamp(phase / 0.1), clamp((1 - phase) / 0.1));
        const clearOfNav = clamp((point.y - 75) / 54);
        const clearOfCopy =
          1 - clamp((point.x - 760) / 95) * clamp((point.y - 220) / 50);
        const intensity = ends * clearOfNav * clearOfCopy * strand.strength;
        const hue = 215 - 52 * Math.cos(phase * Math.PI * 2 + index * 0.45);
        const color = `hsl(${hue} 94% 76%)`;
        group.setAttribute("opacity", String(intensity));
        group.setAttribute("stroke-dashoffset", String(0.045 - phase));
        paint.setAttribute("cx", String(point.x));
        paint.setAttribute("cy", String(point.y));
        paint.setAttribute("color", color);
        if (strand.light) {
          wash.setAttribute("cx", String(point.x + tx * 6));
          wash.setAttribute("cy", String(point.y + ty * 4));
          wash.setAttribute("color", color);
          wash.firstElementChild!.setAttribute(
            "stop-opacity",
            String(intensity * 0.7),
          );
        }
      });
    }
    function syncPreference() {
      cancelAnimationFrame(frame);
      lastTime = 0;
      if (reduced.matches) {
        center();
        x = y = 0;
        outlines.removeAttribute("transform");
        ribbons.removeAttribute("transform");
      } else {
        measure();
        frame = requestAnimationFrame(tick);
      }
    }

    const resize = new ResizeObserver(measure);
    resize.observe(art);
    section.addEventListener("pointermove", follow);
    section.addEventListener("pointerleave", center);
    section.addEventListener("pointercancel", center);
    pointer.addEventListener("change", center);
    reduced.addEventListener("change", syncPreference);
    syncPreference();
    return () => {
      cancelAnimationFrame(frame);
      resize.disconnect();
      section.removeEventListener("pointermove", follow);
      section.removeEventListener("pointerleave", center);
      section.removeEventListener("pointercancel", center);
      pointer.removeEventListener("change", center);
      reduced.removeEventListener("change", syncPreference);
    };
  }, [svg, hero]);
}

export default function Aurora({
  hero,
  paused,
}: {
  hero: RefObject<HTMLElement | null>;
  paused: boolean;
}) {
  const svg = useRef<SVGSVGElement>(null);
  const id = useId();
  const paint = (name: string) => `url(#${id}-${name})`;
  useAuroraMotion(svg, hero, paused);

  return (
    <svg
      ref={svg}
      className="aurora"
      viewBox="0 0 1200 535"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <g id={id + "-words"} className="hero-type">
          <text x="142" y="224">
            AUDIT
          </text>
          <text x="142" y="338">
            YOUR DATA
          </text>
          <text x="142" y="452">
            FLOWS.
          </text>
        </g>
        <linearGradient id={id + "-spectrum"} x1="0" y1=".15" x2="1" y2=".6">
          <stop stopColor="#9affaf" />
          <stop offset=".27" stopColor="#64dcff" />
          <stop offset=".58" stopColor="#baaaff" />
          <stop offset=".78" stopColor="#e4d7ff" />
          <stop offset="1" stopColor="white" />
        </linearGradient>
        <linearGradient id={id + "-silk"} x2=".8" y2=".96">
          <stop stopColor="#9de7ff" />
          <stop offset=".47" stopColor="#baa9fc" />
          <stop offset="1" stopColor="#20272f" />
        </linearGradient>
        <clipPath id={id + "-ribbon"}>
          <path d={sweep} />
          <path d="M134 130 Q188 198 236 160 L279 169 Q195 250 230 278 Q265 332 158 349 L134 353Z" />
        </clipPath>
        <pattern
          id={id + "-grain"}
          width="5"
          height="5"
          patternUnits="userSpaceOnUse"
        >
          <path
            d="M0 1l3 -1m0 4l2 -1"
            stroke="white"
            opacity=".17"
            strokeWidth=".5"
          />
        </pattern>
        {strands.map(({ light }, index) => (
          <g key={index}>
            <radialGradient
              id={`${id}-pulse-${index}`}
              className="pulse-paint"
              gradientUnits="userSpaceOnUse"
            >
              <stop stopColor="currentColor" />
              <stop offset="1" stopColor="currentColor" stopOpacity="0" />
            </radialGradient>
            <radialGradient
              id={`${id}-wash-${index}`}
              className="headline-paint"
              gradientUnits="userSpaceOnUse"
              r={light || 1}
            >
              <stop stopColor="currentColor" stopOpacity="0" />
              <stop offset="1" stopColor="currentColor" stopOpacity="0" />
            </radialGradient>
          </g>
        ))}
      </defs>
      <g className="aurora-strands" fill="none">
        <g stroke="#74747a" strokeWidth=".85">
          {strands.map(({ path }) => (
            <path key={path} d={path} />
          ))}
          <path d="M1077 209 C1045 204 1040 251 1063 251 C1085 252 1093 216 1077 209Z" />
        </g>
        <g className="aurora-light" strokeLinecap="round">
          {strands.map(({ path }, index) => (
            <g
              className="aurora-pulse"
              key={path}
              stroke={paint("pulse-" + index)}
              opacity="0"
              strokeDasharray=".09 .91"
            >
              <path d={path} pathLength="1" strokeWidth="5" opacity=".16" />
              <path d={path} pathLength="1" strokeWidth="1.7" />
            </g>
          ))}
        </g>
      </g>
      <g className="aurora-ribbons">
        <path d={silk} fill={paint("silk")} />
        <path d={silk} fill={paint("grain")} />
        <path d={folds} fill={paint("spectrum")} />
      </g>
      <g className="hero-lettering">
        <use
          href={`#${id}-words`}
          fill="none"
          stroke="#929095"
          strokeWidth=".75"
        />
        <g clipPath={paint("ribbon")}>
          <use href={`#${id}-words`} fill={paint("spectrum")} />
          <g className="aurora-light">
            {strands.map(
              ({ light }, index) =>
                light > 0 && (
                  <use
                    key={index}
                    href={`#${id}-words`}
                    fill={paint("wash-" + index)}
                  />
                ),
            )}
          </g>
        </g>
      </g>
    </svg>
  );
}
