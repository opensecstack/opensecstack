// Post-build prerendering step.
//
// The app is a client-side-only SPA (Vite + React Router v7): dist/index.html
// ships an empty <div id="root">, and every route's real <title>/<meta> tags
// are only set at runtime by react-helmet-async once React mounts. That's
// invisible to crawlers/social-scrapers that don't execute JS, and the
// homepage is the only route with hand-written fallback tags baked into
// index.html.
//
// This script boots the freshly built dist/ output behind a local static
// server (`vite preview`, which already understands the configured `base`),
// visits every real route from src/App.tsx with headless Chrome (puppeteer),
// waits for the route to render (and for react-helmet-async to push its
// tags into <head>), and writes the fully-rendered document out to
// dist/<route>/index.html. GitHub Pages serves <route>/index.html for a
// request to /<route> automatically, so this needs no server-side rewrite
// rule, and it's purely additive: the SPA-redirect script in index.html and
// public/404.html (client-side routing / deep-link support) are untouched —
// client-side navigation still takes over exactly as before once JS loads.
//
// Deliberately NOT react-snap: react-snap's puppeteer/React-18 integration
// is unmaintained and this gives full control over waiting for lazy-loaded
// chunks and Suspense boundaries to settle.

import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import puppeteer from 'puppeteer'
import { preview } from 'vite'

const ROOT = path.resolve(import.meta.dirname, '..')
const DIST = path.join(ROOT, 'dist')
const PORT = 4174
const BASE = (process.env.VITE_BASE_PATH || '/').replace(/\/$/, '') // e.g. '/opensecstack' or ''

// Every route defined in src/App.tsx, excluding the /docs -> /docs/intro
// redirect-only route (its target, /docs/intro, is prerendered via its own
// literal route below) and the catch-all 404 route (there is no single
// static path for it to be written to).
const ROUTES = [
  '/',
  '/runix',
  '/runix/mobile',
  '/docs/intro',
  '/docs/quickstart',
  '/docs/installation',
  '/docs/architecture',
  '/docs/contracts',
  '/docs/platforms',
  '/docs/identity',
  '/docs/governance',
  '/docs/deployment',
  '/docs/security',
  '/docs/platforms/apiguard',
  '/docs/platforms/nis2compass',
  '/docs/platforms/irflow',
  '/docs/platforms/threatflow',
  '/docs/platforms/openscrub',
  '/docs/platforms/cyberpath',
  '/docs/platforms/securelab',
  '/docs/platforms/opencsirt',
  '/docs/platforms/vertguard',
  '/docs/platforms/community',
  '/docs/local-dev',
  '/docs/tds',
  '/docs/citadel-integration',
  '/docs/webhooks',
  '/docs/nis2',
  '/docs/releases',
  '/docs/sdk/go',
  '/docs/sdk/python',
  '/docs/sdk/typescript',
  '/docs/sdk/rust',
  '/docs/citadel/marshal',
  '/docs/citadel/worm',
  '/docs/citadel/sod',
  '/docs/citadel/augur-vigil',
  '/docs/citadel/evidence',
]

// Boots vite's preview server in-process (via vite's JS API) instead of
// shelling out to `npx vite preview`. Spawning npx as a child process proved
// unreliable in this environment (slow cold resolution blew past a startup
// timeout, and a rejected startup left the child orphaned holding the port).
// The programmatic API avoids the subprocess entirely.
async function startPreviewServer() {
  const server = await preview({
    root: ROOT,
    base: process.env.VITE_BASE_PATH || '/',
    preview: { port: PORT, strictPort: true },
  })
  return server
}

async function prerenderRoute(browser, route) {
  const page = await browser.newPage()
  const url = `http://localhost:${PORT}${BASE}${route}`
  try {
    await page.goto(url, { waitUntil: 'networkidle0', timeout: 30000 })
    // Wait for the lazy-loaded route chunk to render real content into
    // #root (Suspense fallback is `null`, so an empty root means "still
    // loading"), then give react-helmet-async's effect a beat to flush its
    // tags into <head>.
    await page.waitForFunction(
      () => {
        const root = document.getElementById('root')
        return !!root && root.children.length > 0
      },
      { timeout: 20000 }
    )
    await new Promise((r) => setTimeout(r, 250))

    const html = await page.evaluate(() => {
      // react-helmet-async injects each route's own <meta>/<link> tags
      // (marked data-rh="true") into <head>, but it only ever removes tags
      // IT previously added — it has no way to know about the hardcoded
      // homepage-fallback description/canonical/OG tags baked into
      // index.html for non-JS crawlers. Left alone, that produces two
      // conflicting tags per key (e.g. two <meta name="description">), with
      // the generic homepage one appearing first — exactly the content a
      // crawler that reads only the first match would pick up. For every
      // head meta[name]/meta[property]/link[rel] that has a react-helmet
      // counterpart with the same key, drop the original non-data-rh tag so
      // only the route-accurate one remains.
      const keyOf = (el) =>
        el.tagName +
        ':' +
        (el.getAttribute('name') || el.getAttribute('property') || el.getAttribute('rel') || '')
      const head = document.head
      const managed = new Set(
        Array.from(head.querySelectorAll('[data-rh="true"]')).map(keyOf)
      )
      head
        .querySelectorAll('meta[name], meta[property], link[rel]')
        .forEach((el) => {
          if (!el.hasAttribute('data-rh') && managed.has(keyOf(el))) {
            el.remove()
          }
        })
      return '<!DOCTYPE html>\n' + document.documentElement.outerHTML
    })
    const outDir = route === '/' ? DIST : path.join(DIST, ...route.split('/').filter(Boolean))
    await mkdir(outDir, { recursive: true })
    await writeFile(path.join(outDir, 'index.html'), html, 'utf8')

    const title = await page.title()
    console.log(`  ok    ${route.padEnd(32)} -> ${path.relative(ROOT, outDir)}/index.html  (${title})`)
  } catch (err) {
    console.error(`  FAIL  ${route.padEnd(32)} ${err.message}`)
    throw err
  } finally {
    await page.close()
  }
}

async function main() {
  console.log(`Prerendering ${ROUTES.length} routes (base="${BASE || '/'}")...`)
  const server = await startPreviewServer()
  let browser
  const failures = []
  try {
    // Note: --disable-gpu is intentionally NOT passed. Several routes (e.g.
    // /runix, /runix/mobile, the homepage) mount a WebGL three.js scene, and
    // with GPU acceleration disabled Chrome's software (SwiftShader) path
    // fails to create a second/third WebGL context once one page has already
    // used one, throwing "Error creating WebGL context" and leaving #root
    // permanently empty on every route opened after the first WebGL page.
    // Leaving GPU compositing on (headless Chrome's own software fallback)
    // lets each page's Canvas mount independently.
    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] })
    for (const route of ROUTES) {
      try {
        await prerenderRoute(browser, route)
      } catch {
        failures.push(route)
      }
    }
  } finally {
    if (browser) await browser.close()
    await new Promise((resolve) => server.httpServer.close(resolve))
  }

  if (failures.length > 0) {
    console.error(`\nPrerendering failed for ${failures.length} route(s): ${failures.join(', ')}`)
    process.exitCode = 1
  } else {
    console.log(`\nPrerendered all ${ROUTES.length} routes successfully.`)
  }
}

main().catch((err) => {
  console.error(err)
  process.exitCode = 1
})
