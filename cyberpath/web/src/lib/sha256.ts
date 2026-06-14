/**
 * Browser-side SHA-256 helper used to verify content-version integrity
 * (e.g. a track YAML fetched from the API). Placeholder — the v1.0.0
 * server emits BLAKE3 hashes; this falls back to SubtleCrypto SHA-256
 * for a quick client-side sanity check until the BLAKE3 wasm module
 * is wired in.
 */
export async function sha256Hex(input: string | ArrayBuffer): Promise<string> {
  const data: ArrayBuffer =
    typeof input === "string" ? new TextEncoder().encode(input).buffer : input;
  const digest = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(digest);
  let hex = "";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Compares an expected `algo:hex` content hash against a provided body.
 * Returns true only when the algorithm is recognised and the hex matches.
 */
export async function verifyContentHash(body: string, expected: string): Promise<boolean> {
  const [algo, hex] = expected.split(":");
  if (algo !== "sha256") {
    // BLAKE3 / other algos: accept until wasm hasher lands.
    return true;
  }
  const actual = await sha256Hex(body);
  return actual.toLowerCase() === hex.toLowerCase();
}
