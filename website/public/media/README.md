# Media assets (Higgsfield AI)

Drop Higgsfield-generated clips here, then wire them up in
[`src/data/media.ts`](../../src/data/media.ts). Nothing renders on the site until
a clip is listed in that file — so an empty or half-finished folder never shows
a broken player.

## Naming convention

For each clip pick a base `<name>` and provide:

| File | Codec | Required? | Purpose |
|------|-------|-----------|---------|
| `<name>.webm` | VP9 / AV1 | optional | Smaller, preferred source |
| `<name>.mp4`  | H.264     | **yes**   | Universal fallback (Safari, etc.) |
| `<name>.jpg`  | —         | recommended | Poster frame shown before the video loads |

Platform clips live under `platforms/` (e.g. `platforms/apiguard.mp4`).

## Where each clip appears

- **Hero background** — set `heroMedia = '<name>'` in `media.ts`.
- **Showcase section** — add an entry to `showcaseMedia` in `media.ts`.
- **Platform card** — add `{ <platformId>: 'platforms/<name>' }` to
  `platformMedia` in `media.ts`. Platform ids are in
  [`src/data/platforms.ts`](../../src/data/platforms.ts).

## Export tips (keep the site fast)

- Target **1080p or smaller**; background clips look great at 720p.
- Keep loops **short (4–8 s)** and seamless — they autoplay muted on loop.
- Re-encode for the web before committing, e.g. with ffmpeg:

  ```bash
  # MP4 (H.264) — universal
  ffmpeg -i higgsfield-export.mp4 -vf scale=1280:-2 -c:v libx264 -crf 24 \
    -preset slow -an -movflags +faststart hero.mp4

  # WebM (VP9) — smaller, preferred where supported
  ffmpeg -i higgsfield-export.mp4 -vf scale=1280:-2 -c:v libvpx-vp9 -crf 33 \
    -b:v 0 -an hero.webm

  # Poster frame from the first second
  ffmpeg -i higgsfield-export.mp4 -ss 0.5 -vframes 1 -q:v 3 hero.jpg
  ```

- Background clips are muted and decorative (no audio track needed — `-an`).

## Attribution / licensing

Higgsfield's output licence depends on your plan. Confirm you have the rights to
publish each clip before committing it to this public repository.
