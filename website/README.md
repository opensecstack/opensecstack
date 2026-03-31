## Deployment

### GitHub Pages

Deployment is automatic. Every push to `main` that touches files under `website/` triggers
the [Deploy Website](.github/workflows/website-deploy.yml) workflow, which uploads the
`website/` directory as a Pages artifact and publishes it.

Live URL: **https://opensecstack.github.io/opensecstack/**

Manual re-deploy: open the workflow in the Actions tab and click **Run workflow**.

### Netlify

**Drag-and-drop:** go to [netlify.com/drop](https://app.netlify.com/drop) and drop the
`website/` folder.

**Connect repo:** create a new Netlify site, point it at this repository, and set the
publish directory to `website/`. The `netlify.toml` in that directory handles security
headers and SPA-style redirects automatically — no further configuration needed.

### Manual / local

```bash
# Python (no install required)
python -m http.server 8000 --directory website/
# Open http://localhost:8000

# Node.js (npx, no global install required)
npx serve website/
# Open http://localhost:3000
```

---

# opensecstack.org

Source for the opensecstack project website.

## Structure

```
website/
  index.html    # Single-page static site (no build step required)
  README.md     # This file
```

The site is a single self-contained HTML file with inline CSS. There are no dependencies,
no build tools, and no npm install required. Open it directly in a browser or serve it
with any static file server.

## Serving Locally

### Python (built-in, no install required)

```bash
cd website
python3 -m http.server 8000
# Open http://localhost:8000
```

### Node.js (npx, no global install required)

```bash
cd website
npx serve .
# Open http://localhost:3000
```

### Docker

```bash
docker run --rm -p 8000:80 \
  -v "$(pwd)/website:/usr/share/nginx/html:ro" \
  nginx:alpine
# Open http://localhost:8000
```

### VS Code Live Server

Install the [Live Server](https://marketplace.visualstudio.com/items?itemName=ritwickdey.LiveServer)
extension, right-click `index.html`, and select **Open with Live Server**.

## Content

The current `index.html` covers:

- Navigation header with links to Documentation, GitHub, and the Get Started section
- Hero section with project tagline and key stats
- Feature cards for APIGuard, NIS2 Compass, and CITADEL
- "How it works" — 3-step journey from API connection to compliance report
- Architecture diagram (ASCII, rendered in a dark code block)
- Get Started section with Docker Compose quickstart and service endpoint reference
- Footer with platform, developer, and community links, Apache-2.0 / AGPL-3.0 licence badges

## Design System

The site uses inline CSS with CSS custom properties. Key tokens:

| Token | Value | Usage |
|-------|-------|-------|
| `--blue` | `#2563EB` | Primary action colour, links, badges |
| `--slate-900` | `#0F172A` | Header, footer, code block backgrounds |
| `--slate-800` | `#1E293B` | Body text |
| `--white` | `#FFFFFF` | Page background |

No external fonts, no framework, no CDN dependencies. The site renders correctly without
any network access.

