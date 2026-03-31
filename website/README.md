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

## Deployment

The site can be deployed to any static hosting service by uploading `index.html`:

- **GitHub Pages:** push to a `gh-pages` branch or configure Pages from the `website/` directory
- **Netlify / Vercel:** point to the `website/` directory as the publish directory
- **Nginx / Caddy:** serve the `website/` directory as the document root
