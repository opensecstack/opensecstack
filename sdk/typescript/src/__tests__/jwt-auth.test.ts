/**
 * Tests for JWT exp parsing and proactive token refresh.
 *
 * Covers:
 *  1. parseJWTExp correctly extracts exp from a valid JWT
 *  2. parseJWTExp returns null for invalid tokens
 *  3. Client proactively refreshes when token is about to expire
 *  4. Client does NOT refresh when token is still valid
 *  5. Client handles refresh failure gracefully (falls back to existing token)
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { parseJWTExp } from "../jwt.js";
import { APIGuardClient } from "../apiguard.js";
import { NIS2CompassClient } from "../nis2compass.js";
import { OpenSecStackError } from "../types.js";

// ---------------------------------------------------------------------------
// Mock fetch
// ---------------------------------------------------------------------------

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);
vi.stubGlobal("crypto", { randomUUID: () => "test-uuid" });

// ---------------------------------------------------------------------------
// JWT helper
// ---------------------------------------------------------------------------

function buildJWT(payload: Record<string, unknown>): string {
  const header = Buffer.from(
    JSON.stringify({ alg: "HS256", typ: "JWT" }),
  ).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.test-signature`;
}

function jsonResponse(body: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ "Content-Type": "application/json" }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}

function authResponse(jwt: string) {
  return jsonResponse({ access_token: jwt });
}

// ---------------------------------------------------------------------------
// 1. parseJWTExp correctly extracts exp from a valid JWT
// ---------------------------------------------------------------------------

describe("parseJWTExp", () => {
  it("extracts exp from a valid JWT", () => {
    const exp = 1700000000;
    const token = buildJWT({ sub: "user-1", exp });
    expect(parseJWTExp(token)).toBe(exp);
  });

  it("returns null for invalid tokens", () => {
    // Not enough segments
    expect(parseJWTExp("")).toBeNull();
    expect(parseJWTExp("one-part")).toBeNull();
    expect(parseJWTExp("two.parts")).toBeNull();
    expect(parseJWTExp("a.b.c.d")).toBeNull();

    // Invalid base64
    expect(parseJWTExp("header.!!!.sig")).toBeNull();

    // No exp claim
    expect(parseJWTExp(buildJWT({ sub: "x" }))).toBeNull();

    // exp is not a number
    expect(parseJWTExp(buildJWT({ exp: "string" }))).toBeNull();
    expect(parseJWTExp(buildJWT({ exp: true }))).toBeNull();
    expect(parseJWTExp(buildJWT({ exp: null }))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 3. Client proactively refreshes when token is about to expire
// ---------------------------------------------------------------------------

describe("APIGuardClient — proactive token refresh", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("proactively refreshes when token expires within 30 seconds", async () => {
    // First auth: return a JWT that expires in 10 seconds (within the 30s buffer)
    const soonExpiringJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 10,
    });
    // Second auth: return a fresh JWT that expires far in the future
    const freshJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    // Call 1: auth (returns soon-expiring token)
    mockFetch.mockResolvedValueOnce(authResponse(soonExpiringJWT));
    // Call 2: API request with soon-expiring token
    mockFetch.mockResolvedValueOnce(jsonResponse([]));
    // Call 3: re-auth (proactive refresh since token expires within 30s)
    mockFetch.mockResolvedValueOnce(authResponse(freshJWT));
    // Call 4: API request with fresh token
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    const client = new APIGuardClient({
      baseURL: "http://localhost:8080",
      apiKey: "test-key",
      maxRetries: 0,
    });

    // First call: authenticates and makes request
    await client.listScans();

    // Second call: token is about to expire (within 30s), should re-authenticate
    await client.listScans();

    // Verify: 2 auth calls + 2 API calls = 4 total
    expect(mockFetch).toHaveBeenCalledTimes(4);

    // Verify the auth calls
    const call0Url = mockFetch.mock.calls[0]![0] as string;
    const call2Url = mockFetch.mock.calls[2]![0] as string;
    expect(call0Url).toContain("/api/v1/auth/token");
    expect(call2Url).toContain("/api/v1/auth/token");

    // Verify the second API call uses the fresh JWT
    const call3Headers = mockFetch.mock.calls[3]![1].headers as Record<string, string>;
    expect(call3Headers["Authorization"]).toBe(`Bearer ${freshJWT}`);
  });

  // ─── 4. Client does NOT refresh when token is still valid ───

  it("does NOT refresh when token is still valid", async () => {
    const validJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 3600, // expires in 1 hour
    });

    // Call 1: auth
    mockFetch.mockResolvedValueOnce(authResponse(validJWT));
    // Call 2: API request
    mockFetch.mockResolvedValueOnce(jsonResponse([]));
    // Call 3: API request (reuses token, no re-auth)
    mockFetch.mockResolvedValueOnce(jsonResponse([]));
    // Call 4: API request (reuses token, no re-auth)
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    const client = new APIGuardClient({
      baseURL: "http://localhost:8080",
      apiKey: "test-key",
      maxRetries: 0,
    });

    await client.listScans();
    await client.listScans();
    await client.listScans();

    // Only 1 auth call + 3 API calls = 4 total (no extra auth calls)
    expect(mockFetch).toHaveBeenCalledTimes(4);

    // Only the first call should be to auth/token
    const authCalls = mockFetch.mock.calls.filter(
      (call) => (call[0] as string).includes("/api/v1/auth/token"),
    );
    expect(authCalls).toHaveLength(1);
  });

  // ─── 5. Client handles refresh failure gracefully ───

  it("handles auth failure gracefully — throws on initial auth failure", async () => {
    // Auth returns 401 — invalid API key
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Unauthorized" }, 401),
    );

    const client = new APIGuardClient({
      baseURL: "http://localhost:8080",
      apiKey: "bad-key",
      maxRetries: 0,
    });

    await expect(client.listScans()).rejects.toThrow(
      "Authentication failed: invalid API key",
    );
  });

  it("handles proactive refresh failure — re-tries auth and propagates error", async () => {
    // First auth: returns a token expiring soon
    const soonExpiringJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 10,
    });
    mockFetch.mockResolvedValueOnce(authResponse(soonExpiringJWT));
    mockFetch.mockResolvedValueOnce(jsonResponse([])); // first API call succeeds

    // Proactive refresh fails (server error)
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Service unavailable" }, 503),
    );

    const client = new APIGuardClient({
      baseURL: "http://localhost:8080",
      apiKey: "test-key",
      maxRetries: 0,
    });

    // First call succeeds
    await client.listScans();

    // Second call triggers proactive refresh which fails
    await expect(client.listScans()).rejects.toThrow("Auth error HTTP 503");
  });
});

// ---------------------------------------------------------------------------
// NIS2CompassClient — same JWT auth behaviour
// ---------------------------------------------------------------------------

describe("NIS2CompassClient — proactive token refresh", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("proactively refreshes when token expires within 30 seconds", async () => {
    const soonExpiringJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 10,
    });
    const freshJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    // NIS2Compass auth response uses "token" key (not "access_token")
    mockFetch.mockResolvedValueOnce(jsonResponse({ token: soonExpiringJWT }));
    mockFetch.mockResolvedValueOnce(jsonResponse([])); // first API call
    mockFetch.mockResolvedValueOnce(jsonResponse({ token: freshJWT }));
    mockFetch.mockResolvedValueOnce(jsonResponse([])); // second API call

    const client = new NIS2CompassClient({
      baseURL: "https://nis2.example.com",
      apiKey: "test-key",
      maxRetries: 0,
    });

    await client.getOrganisations();
    await client.getOrganisations();

    // 2 auth + 2 API = 4 total
    expect(mockFetch).toHaveBeenCalledTimes(4);

    const authCalls = mockFetch.mock.calls.filter(
      (call) => (call[0] as string).includes("/api/v1/auth/token"),
    );
    expect(authCalls).toHaveLength(2);
  });

  it("does NOT refresh when token is still valid", async () => {
    const validJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    mockFetch.mockResolvedValueOnce(jsonResponse({ token: validJWT }));
    mockFetch.mockResolvedValueOnce(jsonResponse([]));
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    const client = new NIS2CompassClient({
      baseURL: "https://nis2.example.com",
      apiKey: "test-key",
      maxRetries: 0,
    });

    await client.getOrganisations();
    await client.getOrganisations();

    // 1 auth + 2 API = 3 total
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});

// ---------------------------------------------------------------------------
// refreshToken updates cached token state (matching Go SDK)
// ---------------------------------------------------------------------------

describe("APIGuardClient.refreshToken — updates cached JWT", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it("refreshToken updates the cached JWT for subsequent requests", async () => {
    const initialJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const refreshedJWT = buildJWT({
      sub: "test",
      exp: Math.floor(Date.now() / 1000) + 7200,
    });

    // Call 1: initial auth
    mockFetch.mockResolvedValueOnce(authResponse(initialJWT));
    // Call 2: first API call
    mockFetch.mockResolvedValueOnce(jsonResponse([]));
    // Call 3: refreshToken
    mockFetch.mockResolvedValueOnce(
      jsonResponse({
        access_token: refreshedJWT,
        refresh_token: "new-refresh",
        expires_in: 7200,
      }),
    );
    // Call 4: subsequent API call (should use refreshed JWT)
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    const client = new APIGuardClient({
      baseURL: "http://localhost:8080",
      apiKey: "test-key",
      maxRetries: 0,
    });

    // Initial request triggers auth
    await client.listScans();

    // Refresh the token
    await client.refreshToken("old-refresh-token");

    // Subsequent request should use the refreshed JWT
    await client.listScans();

    // The last API call should use the refreshed JWT
    const lastHeaders = mockFetch.mock.calls[3]![1].headers as Record<string, string>;
    expect(lastHeaders["Authorization"]).toBe(`Bearer ${refreshedJWT}`);
  });
});
