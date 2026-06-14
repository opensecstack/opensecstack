// Stale compiled artifact of an older App router that (a) used the HS256
// "paste a JWT" Login and (b) was missing the /auth/callback route needed by
// the sinauth popup flow. Vite resolves .js before .tsx, so this shadowed the
// maintained App.tsx. Re-point it at the real component.
//
// The real fix is to delete every stale *.js under src/ (each has a .ts/.tsx
// sibling) and rely on vite.config.ts's resolve.extensions ordering.
export { default } from "./App.tsx";
