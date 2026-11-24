# DPDP Auditor design system

## Foundations

The landing page reserves color for the ribbon, the primary action and the sample statistics. Workspace screens use neutral surfaces so that evidence, severity and review state can be read independently. Keep synthetic data and simulation labels visible at the point of use.

| Role | Value | Use |
| --- | --- | --- |
| Background | #090A0C | Workspace canvas |
| Surface / raised | #18191E / #222329 | Evidence panels and finding cards |
| Border | #34353C | Card edges, controls and divisions |
| Primary / secondary text | #F5F5F7 / #ADAFBA | Titles, body, supporting metadata |
| Violet / blue / mint | #C4AEFF / #A7DFFF / #B9F5D0 | Legal references, review indicators, confirmations |
| Action | #B9FCA1 | Start scan |
| Light surface | #F0F1EE | Dashboard reporting band |
| Rail and divider | #111319 / #252731 | Charcoal navigation rail and its inset divider |
| Rail hover and active | #1E202A / #292535 | Hover and keyboard focus feedback, active route |
| Rail icons | #B4B6C2 / #C4AEFF | Inactive icons, active icon and 3px indicator |

[Global tokens and component styles](../frontend/src/styles.css) · [Workspace layouts and breakpoints](../frontend/src/workspace.css)

## Typography and layout

Use the local Inter, Arial, Helvetica, sans-serif stack. The SVG headline uses Arial with a 105-unit size and −7-unit tracking in a 1200 × 535 viewBox. Its accessible name comes from the page heading. Workspace headings scale from 2rem to 4rem. Use Consolas or monospace for rules, evidence and paths. Smaller status labels accompany the written severity and the review selector.

Use the shared `.type-pixel` utility for Pixelify Sans Medium. The `--font-pixel` token supplies the family, with weight 500, 0.02em tracking and a 1.36 line height. Existing component sizes set the scale. Use it for the landing capability caption, scan sections and stage names, dashboard chart and summary labels, findings column names, evidence and remediation labels, report sections and selected rules table headers. Use sans-serif for page titles, navigation, form controls, explanatory copy and dense table content. Evidence and rule IDs retain their monospace family. The self-hosted Latin subset ships with its SIL Open Font License. [Font license](../frontend/public/fonts/pixelify-sans-OFL.txt) · [Upstream project](https://github.com/google/fonts/tree/main/ofl/pixelifysans)

The floating header sits 2.1% inside the landing edges. The capability strip and pastel panel occupy 76% of the page. Desktop workspace content starts after a 68px rail and uses fluid side padding. Keep neutral borders fine and radius modest, from 6px controls to 12px panels. Chart counts, units and filter scope stay adjacent to the visualization.

Four board columns become two at 1050px and one at 760px. At the smaller breakpoint the rail narrows to 48px, summary bands stack, wide tables scroll within their container, and the hero description moves below the artwork.

## Components and assets

Reuse the heading, severity badge, select, review selector, rail and review provider from [ui.tsx](../frontend/src/ui.tsx). Buttons and links share the button class family. Use Lucide line icons for navigation and capabilities. Keep named links for icon-only navigation, visible focus rings, textual severity, native selects and the keyboard-accessible evidence dialog.

The rail shows one dark tooltip per destination on hover and keyboard focus. The selected route carries a lavender icon and left indicator. Use an inset focus outline so keyboard focus is visible on both active and inactive routes.

The shared brand mark supplies the intro, landing navigation, workspace rail and favicon. The live SVG renders the Aurora hero. The font and images are served locally. [Brand mark](../frontend/public/mark.svg) · [BrandIntro.tsx](../frontend/src/BrandIntro.tsx) · [Aurora artwork](../frontend/src/Aurora.tsx)

## Production refinements (frontend/src/styles)

Tokens live in `frontend/src/styles/base.css`, the frame in `shell.css`, screens in `screens.css` and the landing in `frontend/src/landing/landing.css`.

| Addition | Value | Use |
| --- | --- | --- |
| Severity scale | critical #FFAFA8, high #F3C99D, medium #DFD69B, low #AED3F3, info #B4B6C2 | `.badge.sev-*`, breakdown rows, card edge stripe. The word is always shown next to the colour. |
| Confidence meter | three bars in #A7DFFF | `ConfidenceMeter`: detection confidence, always separate from severity |
| Faint text / sunken | #8B8D98 / #111216 | footnotes and metadata; segmented controls |
| Danger | #FFB5AD on #24181A | error notices and export errors |
| Motion | `--ease-out` cubic-bezier(.22,1,.36,1); `--dur-fast` 160ms, `--dur` 220ms, `--dur-slow` 320ms | every transition |

Typography rules:
- Pixel (`.type-pixel`): section titles inside screens (Evidence, Finding breakdown, Scan coverage, column names, stage names, the landing caption). `.eyebrow` is the small pixel label above page titles.
- Sans (`.fieldlabel`): labels on data such as "DPDP Act, 2023", "Maximum penalty" and "What the law requires". In the pixel face, figures like 2023 were hard to read, so legal and numeric labels stay sans.
- Mono: rule ids, file paths, evidence, code and legal reference chips.

Components (`frontend/src/components`):
- `SeverityBadge` (large variant in a pill), `ConfidenceMeter`, `Notice` (info or error, with a role), `PageSkeleton`, `Heading` (eyebrow, title, sub, actions)
- `FindingsTable` (search, severity chips, rule, provision, confidence; filters in the URL) and `ProvisionChart` (one series, values at the tips, severity breakdown in the tooltip, click to filter)
- `CodeViewer` (masked context as text, flagged line with `aria-current`), `LawCard`, `ExportButtons`, `ReviewSelect` (native select plus a toast with Undo)
- `Shell`: rail with a sliding active indicator, tooltips and a health dot; breadcrumb with the scan's scope chip; skip link

Responsive behaviour: the board goes from four columns to two at 1050px and one at 760px; the light band goes from three to two to one. Under 760px the rail is 48px, the breadcrumb drops its prefix, tables fold location and confidence under the title, and the drawer is full width.
