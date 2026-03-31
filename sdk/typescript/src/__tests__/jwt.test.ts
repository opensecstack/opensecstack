import { describe, it, expect } from "vitest";
import { parseJWTExp } from "../jwt.js";

// ---------------------------------------------------------------------------
// Helper: build a minimal JWT with a given payload
// ---------------------------------------------------------------------------

function buildJWT(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = "test-signature";
  return `${header}.${body}.${signature}`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("parseJWTExp", () => {
  it("extracts exp from a valid JWT", () => {
    const exp = 1700000000;
    const token = buildJWT({ sub: "user-1", exp });
    expect(parseJWTExp(token)).toBe(exp);
  });

  it("returns null when token has fewer than 3 segments", () => {
    expect(parseJWTExp("only-one-part")).toBeNull();
    expect(parseJWTExp("two.parts")).toBeNull();
  });

  it("returns null when token has more than 3 segments", () => {
    expect(parseJWTExp("a.b.c.d")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(parseJWTExp("")).toBeNull();
  });

  it("returns null when payload is not valid JSON", () => {
    // Build a token where the payload is not valid base64/JSON
    expect(parseJWTExp("header.!!!invalid-base64!!!.signature")).toBeNull();
  });

  it("returns null when payload has no exp claim", () => {
    const token = buildJWT({ sub: "user-1", iat: 1700000000 });
    expect(parseJWTExp(token)).toBeNull();
  });

  it("returns null when exp claim is not a number", () => {
    const token = buildJWT({ sub: "user-1", exp: "not-a-number" });
    expect(parseJWTExp(token)).toBeNull();
  });

  it("handles exp = 0", () => {
    const token = buildJWT({ exp: 0 });
    expect(parseJWTExp(token)).toBe(0);
  });

  it("handles large exp values (year 2100+)", () => {
    const exp = 4102444800; // 2100-01-01
    const token = buildJWT({ exp });
    expect(parseJWTExp(token)).toBe(exp);
  });

  it("handles floating-point exp values", () => {
    const exp = 1700000000.5;
    const token = buildJWT({ exp });
    expect(parseJWTExp(token)).toBe(exp);
  });

  it("works with standard base64url encoding (no padding)", () => {
    // Create a payload that produces base64url without padding
    const payload = { exp: 1700000000 };
    const header = Buffer.from('{"alg":"HS256"}').toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    // Ensure there is no padding
    const token = `${header}.${body.replace(/=+$/, "")}.sig`;
    expect(parseJWTExp(token)).toBe(1700000000);
  });
});
