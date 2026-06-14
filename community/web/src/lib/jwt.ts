function base64UrlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? 0 : 4 - (input.length % 4);
  const b64 = (input + "=".repeat(pad)).replace(/-/g, "+").replace(/_/g, "/");
  return atob(b64);
}

export function jwtExpiryMs(token: string): number | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = JSON.parse(
      decodeURIComponent(
        base64UrlDecode(parts[1])
          .split("")
          .map((c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join(""),
      ),
    );
    if (typeof payload.exp !== "number") return null;
    return payload.exp * 1000;
  } catch {
    return null;
  }
}

export function isJwtExpired(token: string, skewMs = 5_000): boolean {
  const exp = jwtExpiryMs(token);
  if (exp === null) return false;
  return Date.now() + skewMs >= exp;
}
