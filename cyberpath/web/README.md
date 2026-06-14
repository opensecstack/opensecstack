# @opensecstack/cyberpath-web

Learner-facing React + Vite + TypeScript frontend for **CyberPath**.

## Local development

```bash
npm install
cp .env.example .env.local
npm run dev
```

The dev server listens on `http://localhost:3006` and proxies `/api`
to `http://localhost:8086` (the CyberPath Go API). For the bilingual
UI swap demo and full bring-up steps, see
[`../docs/quick-start.md`](../docs/quick-start.md).

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server with HMR. |
| `npm run build` | Type-check + production bundle to `dist/`. |
| `npm run preview` | Serve the built bundle locally. |
| `npm run typecheck` | `tsc --noEmit`. |
| `npm run lint` | ESLint over `src/`. |
| `npm run test` | Vitest unit tests. |
| `npm run test:e2e` | Playwright E2E (lands with v0.5.0). |
| `npm run format` | Prettier write. |

## Environment

Vite only exposes `VITE_*`-prefixed variables. The server side uses the
`CYBERPATH_*` prefix; see `../docs/configuration.md`.

| Var | Purpose |
|---|---|
| `VITE_API_BASE_URL` | API origin used by axios. |
| `VITE_DEFAULT_LOCALE` | `sq` (default) or `en`. |
| `VITE_SENTRY_DSN` | Optional. |

## Layout

```
src/
  api/         typed axios wrappers (tracks, lessons, labs, users, coverage)
  components/  Layout, TrackCard, LabTerminal (xterm placeholder), ...
  i18n/        react-i18next setup + sq/en JSON
  lib/         sha256, formatters
  routes/      one file per route, lazy-loaded
  state/       zustand stores (auth, locale)
  styles/      Tailwind globals
```

## Container

```bash
docker build -t opensecstack/cyberpath-web:dev .
docker run --rm -p 8080:80 opensecstack/cyberpath-web:dev
```

The image runs nginx, gzips static assets, proxies `/api` to
`cyberpath-api:8086`, and falls back to `index.html` for SPA routes.
