# DPDP Auditor design handoff

Place this folder at the root of the actual application's repository. Open that repository in Claude and paste the prompt below. The prototype can also run independently from `dpdp-design-handoff/frontend` with `npm ci` and `npm run dev`.

## Prompt for Claude

> Integrate the DPDP Auditor design into this application's existing frontend. Read `dpdp-design-handoff/docs/INTEGRATION_HANDOFF.md` and inspect the real app's components, routes, and data flow first.
>
> Use the prototype as visual direction. Keep the mint mark, Aurora palette, selective Pixelify Sans accents, and accessible motion. You have creative freedom over layout, spacing, breakpoints, component boundaries, and motion timing. Use and adapt the intro, strands, glass navigation, marquee, and charcoal rail where they serve the actual app. If you use the intro, keep it landing-only, skippable, and suppressed with reduced motion. Preserve pause and reduced-motion controls for continuous animation.
>
> Integrate the presentation in small steps using the actual app's existing APIs, authentication, scan flow, report data, and review controls. Preserve evidence masking and the scanner's severity, confidence, and legal mappings. Keep the demo fixtures and simulated scan timer inside this reference folder. Use the actual app's build and tests to verify scan success and failure, findings and reports, keyboard navigation, narrow layouts, and reduced motion.

## What's inside

- [Integration handoff](docs/INTEGRATION_HANDOFF.md) and [design, layout, and motion documentation](docs/)
- [Reusable design skill](.agents/skills/dpdp-auditor-design-system/SKILL.md)
- [Runnable prototype source](frontend/) with the brand SVG, local font and its license, and pinned dependencies
- [Supplied visual and motion references](references/)
