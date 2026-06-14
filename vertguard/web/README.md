# VertGuard Dashboard

Vite + React + TypeScript admin UI for VertGuard.

## Dev

```bash
npm install
npm run dev      # serves on :3009, proxies /api → :8091
```

Login accepts a pasted JWT until the `/api/v1/auth/login` endpoint lands.

## Build

```bash
npm run build    # outputs to dist/
```

## Routes

- `/` — health + module status
- `/scan` — manual prompt scan
- `/threatfeed` — ATLAS coverage
- `/metrics` — link to Prometheus `/metrics`
