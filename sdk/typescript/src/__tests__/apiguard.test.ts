import { describe, it, expect, vi, beforeEach } from "vitest";
import { APIGuardClient } from "../apiguard.js";
import { OpenSecStackError, RateLimitError } from "../types.js";
import type { Scan, Finding, AuditEntry, RefreshTokenResponse } from "../types.js";

// ---------------------------------------------------------------------------
// Mock fetch
// ---------------------------------------------------------------------------

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// crypto.randomUUID is used by HttpClient for X-Request-ID
vi.stubGlobal("crypto", { randomUUID: () => "test-uuid-1234" });

function mockResponse(
  status: number,
  body: unknown,
  headers?: Record<string, string>,
) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({
      "Content-Type": "application/json",
      ...headers,
    }),
    json: async () => body,
    arrayBuffer: async () => new ArrayBuffer(8),
    body: null,
  };
}

function mockRawResponse(
  status: number,
  headers?: Record<string, string>,
) {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.close();
    },
  });
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({
      "Content-Type": "application/octet-stream",
      ...headers,
    }),
    json: async () => ({}),
    arrayBuffer: async () => new ArrayBuffer(8),
    body: stream,
  };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const BASE_URL = "http://localhost:8080";
const API_KEY = "test-api-key-abc123";

const sampleScan: Scan = {
  id: "scan-001",
  spec_url: "https://example.com/openapi.yaml",
  spec_hash: "sha256:abc123",
  target_url: "https://api.example.com",
  status: "completed",
  modules: ["auth", "injection"],
  total_findings: 3,
  critical_count: 1,
  high_count: 1,
  medium_count: 1,
  low_count: 0,
  info_count: 0,
  error_message: "",
  started_at: "2025-01-01T00:00:00Z",
  completed_at: "2025-01-01T00:05:00Z",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:05:00Z",
};

const sampleFinding: Finding = {
  id: "find-001",
  scan_id: "scan-001",
  owasp_id: "API1:2023",
  module_id: "auth",
  title: "Broken Object Level Authorization",
  description: "The endpoint does not verify ownership.",
  remediation: "Add ownership check.",
  severity: "critical",
  cvss_score: 9.1,
  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  endpoint_path: "/api/v1/users/{id}",
  endpoint_method: "GET",
  status: "open",
  triaged_by: "",
  triage_note: "",
  triaged_at: null,
  created_at: "2025-01-01T00:01:00Z",
  updated_at: "2025-01-01T00:01:00Z",
};

const sampleAuditEntry: AuditEntry = {
  id: "audit-001",
  actor_id: "user-001",
  actor_type: "user",
  action: "scan.created",
  resource_type: "scan",
  resource_id: "scan-001",
  ip_address: "127.0.0.1",
  user_agent: "opensecstack-sdk/0.1.0",
  metadata: { foo: "bar" },
  prev_hash: null,
  chain_hash: "sha256:deadbeef",
  created_at: "2025-01-01T00:00:00Z",
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createClient(): APIGuardClient {
  return new APIGuardClient({
    baseURL: BASE_URL,
    apiKey: API_KEY,
    maxRetries: 0, // disable retries to simplify test assertions
    retryWaitBase: 0,
  });
}

/** Extract the URL string from the most recent fetch call. */
function lastFetchURL(): string {
  const [url] = mockFetch.mock.lastCall!;
  return url;
}

/** Extract the init object from the most recent fetch call. */
function lastFetchInit(): RequestInit {
  const [, init] = mockFetch.mock.lastCall!;
  return init;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("APIGuardClient", () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  // ─── 1. createScan ───

  it("createScan sends POST with spec_url body and returns Scan", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, sampleScan));

    const client = createClient();
    const result = await client.createScan("https://example.com/openapi.yaml");

    expect(result).toEqual(sampleScan);
    expect(lastFetchURL()).toContain("/api/v1/scans");
    expect(lastFetchInit().method).toBe("POST");

    const body = JSON.parse(lastFetchInit().body as string);
    expect(body).toEqual({ spec_url: "https://example.com/openapi.yaml" });

    const headers = lastFetchInit().headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${API_KEY}`);
  });

  // ─── 2. createScanFull ───

  it("createScanFull sends POST with full CreateScanOptions body", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, sampleScan));

    const client = createClient();
    const opts = {
      spec_url: "https://example.com/openapi.yaml",
      target: "https://api.example.com",
      modules: ["auth", "injection"],
      auth_type: "bearer",
      auth_token: "tok-123",
    };
    const result = await client.createScanFull(opts);

    expect(result).toEqual(sampleScan);
    expect(lastFetchInit().method).toBe("POST");

    const body = JSON.parse(lastFetchInit().body as string);
    expect(body).toEqual(opts);
  });

  // ─── 3. getScan ───

  it("getScan sends GET /api/v1/scans/:id", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, sampleScan));

    const client = createClient();
    const result = await client.getScan("scan-001");

    expect(result).toEqual(sampleScan);
    expect(lastFetchURL()).toContain("/api/v1/scans/scan-001");
    expect(lastFetchInit().method).toBe("GET");
    expect(lastFetchInit().body).toBeUndefined();
  });

  // ─── 4. listScans with pagination ───

  it("listScans sends GET with pagination params", async () => {
    const scans = [sampleScan];
    mockFetch.mockResolvedValueOnce(mockResponse(200, scans));

    const client = createClient();
    const result = await client.listScans({ page: 2, per_page: 10 });

    expect(result).toEqual(scans);

    const url = lastFetchURL();
    expect(url).toContain("/api/v1/scans");
    expect(url).toContain("page=2");
    expect(url).toContain("per_page=10");
    expect(lastFetchInit().method).toBe("GET");
  });

  // ─── 5. listScans with no params ───

  it("listScans with no params does not include query params", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, []));

    const client = createClient();
    await client.listScans();

    const url = new URL(lastFetchURL());
    // No page or per_page params should be set when not provided
    expect(url.searchParams.has("page")).toBe(false);
    expect(url.searchParams.has("per_page")).toBe(false);
  });

  // ─── 6. deleteScan ───

  it("deleteScan sends DELETE and returns void", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 204,
      headers: new Headers({ "Content-Type": "application/json" }),
      json: async () => null,
    });

    const client = createClient();
    const result = await client.deleteScan("scan-001");

    expect(result).toBeUndefined();
    expect(lastFetchURL()).toContain("/api/v1/scans/scan-001");
    expect(lastFetchInit().method).toBe("DELETE");
  });

  // ─── 7. getFindings ───

  it("getFindings sends GET with scan ID and filter params", async () => {
    const findings = [sampleFinding];
    mockFetch.mockResolvedValueOnce(mockResponse(200, findings));

    const client = createClient();
    const result = await client.getFindings("scan-001", {
      page: 1,
      per_page: 25,
      status: "open",
      severity: "critical",
    });

    expect(result).toEqual(findings);

    const url = lastFetchURL();
    expect(url).toContain("/api/v1/scans/scan-001/findings");
    expect(url).toContain("page=1");
    expect(url).toContain("per_page=25");
    expect(url).toContain("status=open");
    expect(url).toContain("severity=critical");
    expect(lastFetchInit().method).toBe("GET");
  });

  // ─── 8. listFindings ───

  it("listFindings sends GET /api/v1/findings with params", async () => {
    const findings = [sampleFinding];
    mockFetch.mockResolvedValueOnce(mockResponse(200, findings));

    const client = createClient();
    const result = await client.listFindings({
      page: 1,
      per_page: 50,
      scan_id: "scan-001",
    });

    expect(result).toEqual(findings);

    const url = lastFetchURL();
    expect(url).toContain("/api/v1/findings");
    expect(url).not.toContain("/scans/");
    expect(url).toContain("scan_id=scan-001");
    expect(url).toContain("page=1");
    expect(url).toContain("per_page=50");
  });

  // ─── 9. getFinding ───

  it("getFinding sends GET /api/v1/findings/:id", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, sampleFinding));

    const client = createClient();
    const result = await client.getFinding("find-001");

    expect(result).toEqual(sampleFinding);
    expect(lastFetchURL()).toContain("/api/v1/findings/find-001");
    expect(lastFetchInit().method).toBe("GET");
  });

  // ─── 10. patchFinding ───

  it("patchFinding sends PATCH with status and note", async () => {
    const patched: Finding = {
      ...sampleFinding,
      status: "confirmed",
      triage_note: "Verified by security team",
      triaged_by: "user-001",
      triaged_at: "2025-01-02T00:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(mockResponse(200, patched));

    const client = createClient();
    const result = await client.patchFinding("find-001", {
      status: "confirmed",
      note: "Verified by security team",
    });

    expect(result).toEqual(patched);
    expect(lastFetchURL()).toContain("/api/v1/findings/find-001");
    expect(lastFetchInit().method).toBe("PATCH");

    const body = JSON.parse(lastFetchInit().body as string);
    expect(body).toEqual({
      status: "confirmed",
      note: "Verified by security team",
    });
  });

  // ─── 11. getReport ───

  it("getReport returns ArrayBuffer", async () => {
    mockFetch.mockResolvedValueOnce(mockRawResponse(200));

    const client = createClient();
    const result = await client.getReport("scan-001", "pdf");

    expect(result).toBeInstanceOf(ArrayBuffer);

    const url = lastFetchURL();
    expect(url).toContain("/api/v1/scans/scan-001/report");
    expect(url).toContain("format=pdf");
    expect(lastFetchInit().method).toBe("GET");
  });

  // ─── 12. getAuditLog ───

  it("getAuditLog sends GET with limit and page params", async () => {
    const entries = [sampleAuditEntry];
    mockFetch.mockResolvedValueOnce(mockResponse(200, entries));

    const client = createClient();
    const result = await client.getAuditLog(25, 3);

    expect(result).toEqual(entries);

    const url = lastFetchURL();
    expect(url).toContain("/api/v1/audit");
    expect(url).toContain("limit=25");
    expect(url).toContain("page=3");
    expect(lastFetchInit().method).toBe("GET");
  });

  // ─── 13. refreshToken ───

  it("refreshToken sends POST with refresh_token body", async () => {
    const tokenResp: RefreshTokenResponse = {
      access_token: "new-access-token",
      refresh_token: "new-refresh-token",
      expires_in: 3600,
    };
    mockFetch.mockResolvedValueOnce(mockResponse(200, tokenResp));

    const client = createClient();
    const result = await client.refreshToken("old-refresh-token");

    expect(result).toEqual(tokenResp);
    expect(lastFetchURL()).toContain("/api/v1/auth/refresh");
    expect(lastFetchInit().method).toBe("POST");

    const body = JSON.parse(lastFetchInit().body as string);
    expect(body).toEqual({ refresh_token: "old-refresh-token" });
  });

  // ─── 14. Server error (500) ───

  it("throws OpenSecStackError on 500 server error", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse(500, { error: "Internal Server Error" }),
    );

    const client = createClient();
    await expect(client.listScans()).rejects.toThrow(OpenSecStackError);

    try {
      await createClient().listScans();
    } catch (err) {
      // Reset mock for second call
    }

    // Verify the error properties
    mockFetch.mockReset();
    mockFetch.mockResolvedValueOnce(
      mockResponse(500, { error: "Internal Server Error" }),
    );

    try {
      await createClient().listScans();
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(OpenSecStackError);
      expect((err as OpenSecStackError).statusCode).toBe(500);
      expect((err as OpenSecStackError).message).toBe("Internal Server Error");
    }
  });

  // ─── 15. Rate limit (429) ───

  it("throws RateLimitError on 429 response", async () => {
    mockFetch.mockResolvedValue(
      mockResponse(429, { error: "Too Many Requests" }, { "Retry-After": "30" }),
    );

    const client = createClient();

    try {
      await client.getScan("scan-001");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(RateLimitError);
      expect((err as RateLimitError).retryAfter).toBe(30);
    }
  });

  // ─── 16. Not found (404) ───

  it("throws OpenSecStackError with 404 on not found", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse(404, { error: "Scan not found" }),
    );

    const client = createClient();

    try {
      await client.getScan("nonexistent-id");
      expect.unreachable("Should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(OpenSecStackError);
      expect((err as OpenSecStackError).statusCode).toBe(404);
      expect((err as OpenSecStackError).message).toBe("Scan not found");
    }
  });

  // ─── 17. Authorization header is always present ───

  it("includes Authorization Bearer header on every request", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, []));
    mockFetch.mockResolvedValueOnce(mockResponse(200, sampleScan));
    mockFetch.mockResolvedValueOnce(mockResponse(200, []));

    const client = createClient();

    await client.listScans();
    let headers = mockFetch.mock.calls[0]![1].headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${API_KEY}`);

    await client.getScan("scan-001");
    headers = mockFetch.mock.calls[1]![1].headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${API_KEY}`);

    await client.getAuditLog();
    headers = mockFetch.mock.calls[2]![1].headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${API_KEY}`);
  });

  // ─── 18. getAuditLog defaults ───

  it("getAuditLog uses default limit of 50 when called with no args", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse(200, []));

    const client = createClient();
    await client.getAuditLog();

    const url = lastFetchURL();
    expect(url).toContain("limit=50");
    expect(url).not.toContain("page=");
  });

  // ─── 19. uploadSpec sends FormData ───

  it("uploadSpec sends FormData", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse(200, { spec_path: "/specs/test.yaml", spec_hash: "abc123", size: 1024 }),
    );

    const client = createClient();
    const file = new Blob(["openapi: 3.0.0"], { type: "text/yaml" });
    const result = await client.uploadSpec(file, "test.yaml");

    expect(result.spec_hash).toBe("abc123");

    const [, init] = mockFetch.mock.calls[0];
    expect(init.body).toBeInstanceOf(FormData);
    // Content-Type should NOT be explicitly set (FormData sets it with boundary)
    expect(init.headers["Content-Type"]).toBeUndefined();
  });

  // ─── 20. getReport default format ───

  it("getReport defaults to json format", async () => {
    mockFetch.mockResolvedValueOnce(mockRawResponse(200));

    const client = createClient();
    await client.getReport("scan-001");

    const url = lastFetchURL();
    expect(url).toContain("format=json");
  });
});
