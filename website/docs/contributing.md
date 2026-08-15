# Contributing to the OpenSecStack Website

The website is the public face of the ecosystem — a React + TypeScript
+ Vite SPA with a Three.js ecosystem scene. It is intentionally kept at
v0.x (see the root [README](../../README.md) for the reasoning) so
contributors can change anything without bureaucracy.

For the stack and deployment targets, see the [website README](../README.md).

## Setup

```bash
cd website/
npm install
npm run dev        # Vite dev server on http://localhost:5173
```

Requirements: Node.js ≥ 18, npm ≥ 9.

## Content inventory

The homepage is a long-scroll SPA composed from section components in
[`src/sections/`](../src/sections/). Each section renders independently
and is reachable via the navbar's anchor links.

| Section | Component | Maintained by |
|---|---|---|
| Hero | `HeroSection.tsx` | Marketing wording — update when ecosystem positioning shifts |
| Platforms overview | `PlatformsSection.tsx` | Reads from [`src/data/platforms.ts`](../src/data/platforms.ts) — update there, not in JSX |
| Per-platform deep-dives (APIGuard, NIS2 Compass, CITADEL, ThreatFlow, IRFlow, Runix, OpenScrub, CyberPath, SecureLab, OpenCSIRT) | `<Platform>Section.tsx` | Each platform's maintainers |
| SDKs | `SDKSection.tsx` | Reads from the SDK repos — update the code samples when the real SDK API changes |
| Roadmap | `RoadmapSection.tsx` | Update when phases complete or new ones land |

Two additional routes exist:

| Route | Component |
|---|---|
| `/runix` | [`src/pages/RunixPage.tsx`](../src/pages/RunixPage.tsx) |
| `/runix/mobile` | [`src/pages/RunixMobilePage.tsx`](../src/pages/RunixMobilePage.tsx) |

And the SPA 404 catch-all at [`src/pages/NotFoundPage.tsx`](../src/pages/NotFoundPage.tsx).

## Data-driven content

Whenever a section lists entities (platforms, SDK targets, Runix
layers, NIS2 measures), the data lives in `src/data/`:

| File | Purpose |
|---|---|
| `platforms.ts` | Canonical list of platforms shown in the Platforms section, search index, and navbar |
| `runix.ts` | Desktop OS layers, sandbox tiers, phases |
| `runixMobile.ts` | Mobile-specific variant |
| `nis2Measures.ts` | Article 21(2) measure catalogue |
| `marshalGates.ts` | MARSHAL 5-gate definitions |

**Update the data file, not the JSX.** Adding a platform is a
one-line change in `platforms.ts`; the Platforms section and the
navbar search both pick it up automatically.

## Internationalisation

Two languages are supported out of the box: English (default) and
Albanian. Translations live in [`src/i18n/`](../src/i18n/).

### Translation key structure

```
{
  "nav": {
    "platforms": "Platforms",
    "apiguard":  "APIGuard",
    ...
  },
  "hero": {
    "title":    "...",
    "subtitle": "..."
  },
  "section.<sectionid>": { ... }
}
```

Keys are dot-separated paths, grouped by section. To add a new key:

1. Add the English version to [`src/i18n/en.ts`](../src/i18n/en.ts).
2. Add the Albanian version to [`src/i18n/al.ts`](../src/i18n/al.ts)
   — use the same key, never leave a language untranslated in prod.
3. Use via `const { t } = useI18n(); t('your.key')`.

### Adding a new language

1. Create `src/i18n/<code>.ts` mirroring the English shape.
2. Register the language in [`src/i18n/useI18n.ts`](../src/i18n/useI18n.ts).
3. Add the toggle UI for it in the navbar — today the toggle cycles
   English ↔ Albanian; a three-language setup needs a small dropdown
   instead.

### Translation guidelines

- Prefer short, concrete phrases over long prose. The site reads best
  at a sentence-per-bullet cadence.
- Keep MITRE ATT&CK, NIS2, and other proper names untranslated.
- When the English uses a technical term (e.g. "WORM log"), translate
  the surrounding sentence but keep the term — readers searching for
  "WORM" in Albanian documentation will find it.

## Styling

All styles are inline React `style` props and CSS custom properties in
[`src/index.css`](../src/index.css). There is no CSS-in-JS framework
and no Tailwind — a deliberate choice to keep the bundle small and the
dev loop quick.

The palette is defined as CSS variables in `:root { ... }` of
`index.css`. Do not introduce new colours in component JSX; extend the
variable set and reference it.

## Testing

There is no automated test suite in v0.x. Manual verification:

```bash
npm run typecheck    # strict TypeScript check
npm run build        # production build — fails on any TS error
```

Smoke-test the following scenarios locally before opening a PR:

- Navbar collapses correctly below 820px and expands above it.
- Dark-mode toggle persists across reloads.
- Language toggle persists across reloads.
- The SPA 404 page renders for `/nonexistent` without losing theme state.
- WebGL fails gracefully — disable hardware acceleration in the
  browser and confirm the static content still renders (the
  `ErrorBoundary` around `EcosystemScene` is what guarantees this).

Automated tests are tracked for a future v1.0 if the site grows enough
to warrant them.

## Adding a new platform section

1. Add the platform to [`src/data/platforms.ts`](../src/data/platforms.ts).
2. Create `src/sections/<PlatformName>Section.tsx` following the shape
   of an existing section (e.g. `ThreatFlowSection.tsx`).
3. Import and render it in [`src/App.tsx`](../src/App.tsx) inside
   `<HomePage>`.
4. Add translation keys in both `en.ts` and `al.ts`.
5. Verify the navbar search picks up the new platform (it reads from
   `platforms.ts`; no extra wiring needed).

## Pull request checklist

- [ ] `npm run typecheck` passes.
- [ ] `npm run build` passes.
- [ ] Manual smoke tests above run cleanly.
- [ ] New strings have both English and Albanian translations.
- [ ] Data-driven changes are in `src/data/`, not hard-coded in JSX.
- [ ] No new runtime dependencies added without discussion (bundle size matters).

## Deployment

The site deploys from `main` via the GitHub Pages / Netlify workflow
configured in [`netlify.toml`](../netlify.toml). Merges to `main`
trigger a rebuild and publish automatically; there is no manual
release step.

## Licence

Apache-2.0 — same as the code. Visual design contributions are welcome;
do not submit content you don't have the right to relicence.
