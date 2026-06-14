// This file was a stale compiled artifact of an older HS256 "paste a JWT"
// login screen. Vite's default module resolution prefers .js over .tsx, so it
// was shadowing the maintained Login.tsx (which offers the sinauth SSO flow)
// and forcing users to paste a raw JWT. Rather than delete the artifact, it is
// re-pointed at the real TypeScript component so the SSO login is served.
//
// The real fix is to remove all stale *.js files under src/ (they all have a
// .ts/.tsx sibling) and rely on vite.config.ts's resolve.extensions ordering.
export { default } from "./Login.tsx";
