---
name: dpdp-auditor-design-system
description: Build, refine, or integrate the reference-driven DPDP Auditor React interface, including its aurora landing page, scan workflow, analytical dashboard, review board, and masked evidence views.
---

# DPDP Auditor frontend

For production integration, follow the creative direction in [the package README](../../../README.md). The real application's structure and workflows guide implementation decisions.

Start with the route and its supplied visual reference in [the page specifications](../../../docs/PAGE_SPECIFICATIONS.md). Check the corresponding screen under [the frontend source](../../../frontend/src/) before changing shared decisions.

Use [the design system](../../../docs/DESIGN_SYSTEM.md) for surfaces, typography, grid, controls, assets and responsive behavior. The SVG outline and gradient intersection, grouped dashboard metrics, contrasting lower band, charcoal workspace rail, and compact board cards are examples. Adapt their composition and keep the shared visual identity.

For the landing-only brand introduction, landing strands, synchronized headline color, mouse parallax, glass navigation, marquee, card movement, detail overlays or scan progression, consult [the motion guidelines](../../../docs/MOTION_GUIDELINES.md). If you use the intro or marquee, preserve session-based playback, the skip or pause control, and reduced-motion fallbacks. Use the shared pixel utility for selective section and stage labels. Keep native keyboard and touch status controls available. Review movement updates a separate map keyed by stable finding ID.

For a production port, follow [the integration handoff](../../../docs/INTEGRATION_HANDOFF.md). Read scope, line, masked evidence, severity and confidence from the selected report. Reuse the host application's data and authorization flow. The local timer and fixture belong to the standalone prototype.

Check resulting desktop layouts against the supplied images, verify narrow-screen behavior and run the frontend build. Exercise the affected route with project-, file- and line-scoped records where applicable.

## In this repository

The design is integrated in `frontend/` (see "Integration status" in the integration handoff). When changing it:
- Use the tokens and classes in `frontend/src/styles/` (`base.css`, `shell.css`, `screens.css`) and `frontend/src/landing/landing.css`; do not add one-off colours.
- Use the pixel face only through `.type-pixel` / `.eyebrow`; data labels use `.fieldlabel`.
- Show severity with `SeverityBadge` and detection confidence with `ConfidenceMeter`, side by side and never merged.
- Read findings only from the selected report (`useScan()`) and review status only through `useReviews()` / `ReviewSelect`; never edit scanner fields.
- Run `npm run build` and `npm run e2e` (against the running backend) in `frontend/`. The end-to-end test covers success, failure, the board, keyboard order, reduced motion and 390 px layouts.
