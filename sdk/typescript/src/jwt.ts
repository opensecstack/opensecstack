/**
 * JWT exp claim parser.
 *
 * Decodes the payload segment of a JWT (without any external library) and
 * extracts the `exp` (expiry) claim as a Unix timestamp in seconds.
 *
 * This is used by the SDK clients to proactively refresh tokens before they
 * expire, matching the Go and Python SDKs (SDK-M5).
 */

/**
 * Parse the `exp` claim from a JWT token string.
 *
 * JWTs are three base64url-encoded segments separated by dots. The second
 * segment is the JSON payload containing claims. This function decodes it
 * and returns the `exp` field (Unix timestamp in seconds) or `null` if the
 * token is malformed or lacks an `exp` claim.
 *
 * @param token - A JWT string (e.g. from an auth/token response)
 * @returns The `exp` claim as a Unix timestamp (seconds), or `null`
 */
export function parseJWTExp(token: string): number | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    // Base64url decode the payload segment. Buffer handles the missing
    // padding automatically when using "base64url" encoding.
    const payloadSegment = parts[1]!;
    const payload = JSON.parse(
      Buffer.from(payloadSegment, "base64url").toString("utf-8"),
    );

    return typeof payload.exp === "number" ? payload.exp : null;
  } catch {
    return null;
  }
}
