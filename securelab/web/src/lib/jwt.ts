export interface JwtPayload {
  exp?: number;
  sub?: string;
  role?: string;
  [k: string]: unknown;
}

function base64UrlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? 0 : 4 - (input.length % 4);
  const b64 = (input + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  if (typeof atob === "function") return atob(b64);
  return Buffer.from(b64, "base64").toString("binary");
}

export function decodeJwt(token: string): JwtPayload | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = decodeURIComponent(
      base64UrlDecode(parts[1])
        .split("")
        .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
        .join(""),
    );
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

export function jwtExpiryMs(token: string): number | null {
  const p = decodeJwt(token);
  if (!p || typeof p.exp !== "number") return null;
  return p.exp * 1000;
}

export function isJwtExpired(token: string, skewMs = 5_000): boolean {
  const exp = jwtExpiryMs(token);
  if (exp === null) return false;
  return Date.now() + skewMs >= exp;
}
