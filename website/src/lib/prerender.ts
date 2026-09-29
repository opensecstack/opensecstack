// scripts/prerender.mjs flags the page before navigation so routes can skip
// mounting heavy, purely-decorative work (WebGL scenes) that the crawler-facing
// static HTML doesn't need and that pegs the CPU hard enough on constrained
// CI runners to stall Puppeteer's networkidle0 wait past its timeout.
export function isPrerendering(): boolean {
  return typeof window !== 'undefined' && (window as Window & { __PRERENDER__?: boolean }).__PRERENDER__ === true
}
