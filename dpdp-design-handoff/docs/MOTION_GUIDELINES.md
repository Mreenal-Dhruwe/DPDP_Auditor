# Motion guidelines

The 8.33-second reference transitions from overview to board, lifts a card from Triaged, opens an insertion space in In Progress and settles the card upright. A right-hand evidence drawer then opens over a blurred board. The prototype uses the drag and evidence sequence for interaction, with navigation under user control.

| Interaction | Implementation |
| --- | --- |
| Landing entrance | 750ms opacity reveal on the headline. |
| Controls | 180ms hover transitions. Raised action links move upward by 1px. |
| Workspace navigation | 220ms ease-out fade on page content. |
| Board move | Native HTML drag image follows the pointer. The source becomes translucent with a dashed outline. A striped destination cue names the new status. Motion layout and shared finding IDs animate placement over 240ms. Cards retain fixture order within each status. |
| Evidence | Board card navigation opens a native modal dialog with a 220ms slide from the right. Escape, the close control and browser Back return to the board. |
| Scan | Each mock stage occupies 900ms. After the final stage the completion message remains for 850ms before the dashboard opens. |
| Reduced motion | CSS media queries minimize animations, MotionConfig follows user preferences and the chart respects useReducedMotion. Scan timing and status text remain available. |

[Board and detail interactions](../frontend/src/Findings.tsx) · [Scan timer](../frontend/src/Scan.tsx) · [Motion styles](../frontend/src/workspace.css)

## Landing motion

The brand intro adapts the lower-left panel labeled Concept 1. Its dark glass tile resolves into the existing DPDP mark, then opens a feathered radial aperture onto the real landing page. [Concept1.mp4](../references/Concept1.mp4)

| Intro time | Action |
| --- | --- |
| 0–420ms | The mint mark fades in and scales from 82% to full size. |
| 340–880ms | The translucent glass tile forms around the mark. |
| 880–1430ms | The tile widens for the compact DPDP Auditor wordmark. |
| 1430–1900ms | The wordmark retracts and the mark returns to the center. |
| 1870–2600ms | A radial CSS mask expands from the mark to 76vmax using `cubic-bezier(0.56, 0.03, 0.29, 1)`. Mint and lavender trace the edge before the overlay clears. |

CSS keyframes share one 2.6-second duration. The overlay is mounted only by the landing route and records playback in session storage when it opens. Escape, the Skip intro button, a live reduced-motion preference change, animation completion or the 2.9-second fallback removes the overlay. Reduced-motion visits show the landing page immediately. While the introduction is visible, the underlying page mounts in an inert state. Dismissal restores access and returns focus to the landing region when the skip button had focus. [BrandIntro.tsx](../frontend/src/BrandIntro.tsx) · [brand-intro.css](../frontend/src/brand-intro.css)

- **Strands and lettering.** One 10.4-second animation frame clock drives luminous dashes along the existing SVG geometry. The five paths start at offsets of 10%, 53%, 32%, 72% and 86% of their individual lengths. The dash and radial gradient share the same sampled path point. The three paths near the headline also paint a broader wash clipped to its filled letters, using the pulse's hue, position and intensity. The pulses fade at the path ends and near the navigation and supporting copy. [Aurora.tsx](../frontend/src/Aurora.tsx)
- **Parallax.** Normalize mouse coordinates against the hero and ease to the target with a 145ms time constant. Strands move up to 6px horizontally and 4px vertically. The silk and folds move up to 11px horizontally and 7px vertically. The pointer leaving the hero restores neutral. Only decorative groups move, and the art wrapper clips them to the hero. The effect requires a mouse with fine-pointer and hover support. [Aurora.tsx](../frontend/src/Aurora.tsx)
- **Navigation.** One translucent capsule follows the hovered link or the keyboard-focused link. Motion springs its position and dimensions with stiffness 410 and damping 34. Opacity transitions over 160ms. An independent focus outline and translucent CSS background provide visible feedback when blur is unavailable. [Landing.tsx](../frontend/src/Landing.tsx)
- **Capability marquee.** Each copy of the capability list spans at least one viewport of the strip. The track translates from −50% to 0 over 30 seconds at constant speed, moving left to right. An edge mask fades entering and exiting items. Only the first list is exposed to assistive technology. [landing-motion.css](../frontend/src/landing-motion.css)
- **Motion preferences.** The pause button beside the capability caption freezes the marquee and hero clock and lets parallax return to neutral. Reduced motion turns off the ambient effects and shows a single wrapping list. Navigation focus remains visible and the glass snaps into place. [Landing.tsx](../frontend/src/Landing.tsx) · [landing-motion.css](../frontend/src/landing-motion.css)
- **Hero text selection.** Disable selection on the decorative SVG wrapper to avoid blue selection blocks on painted glyphs. The semantic heading and selectable supporting copy sit outside this wrapper. [landing-motion.css](../frontend/src/landing-motion.css)

## Production motion (frontend/)

| Interaction | Implementation |
| --- | --- |
| Page entry | `.arrive` 220ms opacity; on the landing the hero copy rises over 600ms after 150ms |
| Rail | the active background and 3px violet edge slide between routes (motion `layoutId`, spring 520 / 42); tooltips fade and slide 4px in 160ms |
| Buttons | 1px hover lift; press scale 0.985 in 60ms; the mint button gains a soft glow |
| Breakdown and tracks | bar widths and track scales transition over 320ms when filters change |
| Provision chart | 420ms bar entry, off with reduced motion (`useReducedMotion`) |
| Board | cards keep a shared `layoutId`, so a moved card glides to its new column (spring 520 / 40) instead of fading out and in; the dragged source turns translucent and dashed; the target column gains a mint border and a striped "Move to …" cue; the column count pops briefly |
| Review feedback | a toast (220ms rise) names the move and offers Undo for five seconds |
| Drawer | native dialog, 220ms slide from the right over a 3px blurred backdrop |
| Scan progress | the gradient bar eases over 600ms; stage icons change state; elapsed time ticks every second |
| Loading | skeleton shimmer (1.4s), static with reduced motion |
| Aurora | as in the prototype, plus the animation loop sleeps while the hero is out of view (IntersectionObserver) |

Drag and drop: columns accept a drag from a ref set at `dragstart` and cancel both `dragenter` and `dragover`, so the first event after the drag starts already counts. The status select on each card is the keyboard, touch and screen-reader path for the same move.

Reduced motion: the global media query cuts animations and transitions to near zero, MotionConfig follows the user setting, the intro never mounts, and the marquee becomes one static list with no pause control.
