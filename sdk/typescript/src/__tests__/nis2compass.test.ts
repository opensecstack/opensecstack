import { describe, it, expect, vi, beforeEach } from "vitest";
import { NIS2CompassClient } from "../nis2compass.js";
import { OpenSecStackError } from "../types.js";

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Suppress crypto.randomUUID for request IDs
vi.stubGlobal("crypto", { randomUUID: () => "test-request-id" });

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ "Content-Type": "application/json" }),
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  } as unknown as Response;
}

function emptyResponse(status = 204): Response {
  return {
    ok: true,
    status,
    headers: new Headers({}),
    json: () => Promise.reject(new Error("no body")),
    text: () => Promise.resolve(""),
  } as unknown as Response;
}

function binaryResponse(data: ArrayBuffer): Response {
  return {
    ok: true,
    status: 200,
    headers: new Headers({ "Content-Type": "application/octet-stream" }),
    arrayBuffer: () => Promise.resolve(data),
    json: () => Promise.reject(new Error("not json")),
  } as unknown as Response;
}

const BASE_URL = "https://nis2.example.com";
const API_KEY = "test-api-key-123";

function createClient() {
  return new NIS2CompassClient({
    baseURL: BASE_URL,
    apiKey: API_KEY,
    maxRetries: 0,
  });
}

function lastFetchCall() {
  const [url, init] = mockFetch.mock.calls[mockFetch.mock.calls.length - 1]!;
  return { url: url as string, init: init as RequestInit };
}

describe("NIS2CompassClient", () => {
  let client: NIS2CompassClient;

  beforeEach(() => {
    mockFetch.mockReset();
    client = createClient();
  });

  // ─── Organisations ───

  it("1. createOrganisation — POST body and return value", async () => {
    const created = {
      id: "org-1",
      name: "Acme Corp",
      industry: "technology",
      country: "DE",
      size: "large",
      entity_type: "essential",
      registration_number: "HRB-12345",
      contact_email: "admin@acme.de",
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(created, 201));

    const result = await client.createOrganisation({
      name: "Acme Corp",
      industry: "technology",
      country: "DE",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("Acme Corp");
    expect(body.industry).toBe("technology");
    expect(body.country).toBe("DE");
    expect(result).toEqual(created);
  });

  it("2. getOrganisations — GET with pagination", async () => {
    const orgs = [
      { id: "org-1", name: "Acme" },
      { id: "org-2", name: "Beta" },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(orgs));

    const result = await client.getOrganisations({ page: 2, per_page: 10 });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations");
    expect(url).toContain("page=2");
    expect(url).toContain("per_page=10");
    expect(init.method).toBe("GET");
    expect(result).toEqual(orgs);
  });

  it("3. getOrganisation — GET by ID", async () => {
    const org = { id: "org-42", name: "Test Org" };
    mockFetch.mockResolvedValueOnce(jsonResponse(org));

    const result = await client.getOrganisation("org-42");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations/org-42");
    expect(init.method).toBe("GET");
    expect(result).toEqual(org);
  });

  it("4. patchOrganisation — PATCH with partial fields", async () => {
    const patched = { id: "org-1", name: "Acme Updated", industry: "finance" };
    mockFetch.mockResolvedValueOnce(jsonResponse(patched));

    const result = await client.patchOrganisation("org-1", {
      name: "Acme Updated",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations/org-1");
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(body.name).toBe("Acme Updated");
    expect(result).toEqual(patched);
  });

  it("5. deleteOrganisation — DELETE 204", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));

    const result = await client.deleteOrganisation("org-1");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations/org-1");
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  // ─── Assessments ───

  it("6. createAssessment — POST to org-scoped URL", async () => {
    const assessment = {
      id: "asmt-1",
      org_id: "org-1",
      title: "Q1 Assessment",
      status: "draft",
      framework_version: "2.0",
      scope: "full",
      assessor: "auditor@acme.de",
      due_date: "2026-06-01",
      completed_at: null,
      created_at: "2026-01-01T00:00:00Z",
      updated_at: "2026-01-01T00:00:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(assessment, 201));

    const result = await client.createAssessment("org-1", {
      title: "Q1 Assessment",
      framework_version: "2.0",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations/org-1/assessments");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.title).toBe("Q1 Assessment");
    expect(body.framework_version).toBe("2.0");
    expect(result).toEqual(assessment);
  });

  it("7. getAssessments — GET with status filter", async () => {
    const assessments = [{ id: "asmt-1", status: "in_progress" }];
    mockFetch.mockResolvedValueOnce(jsonResponse(assessments));

    const result = await client.getAssessments("org-1", {
      status: "in_progress",
      page: 1,
      per_page: 25,
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/organisations/org-1/assessments");
    expect(url).toContain("status=in_progress");
    expect(url).toContain("page=1");
    expect(url).toContain("per_page=25");
    expect(init.method).toBe("GET");
    expect(result).toEqual(assessments);
  });

  it("8. getAssessment — GET by ID", async () => {
    const assessment = { id: "asmt-99", title: "Full Audit" };
    mockFetch.mockResolvedValueOnce(jsonResponse(assessment));

    const result = await client.getAssessment("asmt-99");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-99");
    expect(init.method).toBe("GET");
    expect(result).toEqual(assessment);
  });

  it("9. patchAssessment — PATCH status transition", async () => {
    const patched = { id: "asmt-1", status: "completed" };
    mockFetch.mockResolvedValueOnce(jsonResponse(patched));

    const result = await client.patchAssessment("asmt-1", {
      status: "completed",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1");
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(body.status).toBe("completed");
    expect(result).toEqual(patched);
  });

  it("10. deleteAssessment — DELETE 204", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));

    const result = await client.deleteAssessment("asmt-1");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1");
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  // ─── Controls ───

  it("11. listControls — GET with filters", async () => {
    const controls = [
      { id: "ctrl-1", measure_ref: "ART21.2a", status: "compliant" },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(controls));

    const result = await client.listControls("asmt-1", {
      status: "compliant",
      nist_category: "PR",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/controls");
    expect(url).toContain("status=compliant");
    expect(url).toContain("nist_category=PR");
    expect(init.method).toBe("GET");
    expect(result).toEqual(controls);
  });

  it("12. getControl — GET by assessment + measure ref", async () => {
    const control = {
      id: "ctrl-1",
      assessment_id: "asmt-1",
      measure_ref: "ART21.2a",
      title: "Risk analysis policies",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(control));

    const result = await client.getControl("asmt-1", "ART21.2a");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/controls/ART21.2a");
    expect(init.method).toBe("GET");
    expect(result).toEqual(control);
  });

  it("13. patchControl — PATCH with evidence and risk_score", async () => {
    const patched = {
      id: "ctrl-1",
      measure_ref: "ART21.2a",
      status: "partially_compliant",
      evidence: { doc: "risk-policy-v3.pdf" },
      risk_score: 7.5,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(patched));

    const result = await client.patchControl("asmt-1", "ART21.2a", {
      status: "partially_compliant",
      evidence: { doc: "risk-policy-v3.pdf" },
      risk_score: 7.5,
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/controls/ART21.2a");
    expect(init.method).toBe("PATCH");
    const body = JSON.parse(init.body as string);
    expect(body.evidence).toEqual({ doc: "risk-policy-v3.pdf" });
    expect(body.risk_score).toBe(7.5);
    expect(result).toEqual(patched);
  });

  // ─── Artifacts ───

  it("14. listArtifacts — GET list", async () => {
    const artifacts = [
      { id: "art-1", filename: "policy.pdf", type: "policy" },
      { id: "art-2", filename: "scan.json", type: "scan_result" },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(artifacts));

    const result = await client.listArtifacts("asmt-1");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/artifacts");
    expect(init.method).toBe("GET");
    expect(result).toEqual(artifacts);
  });

  it("15. getArtifact — GET by ID", async () => {
    const artifact = {
      id: "art-42",
      filename: "evidence.pdf",
      type: "evidence",
      size_bytes: 102400,
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(artifact));

    const result = await client.getArtifact("art-42");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/artifacts/art-42");
    expect(init.method).toBe("GET");
    expect(result).toEqual(artifact);
  });

  it("16. downloadArtifact — returns ArrayBuffer", async () => {
    const binaryData = new ArrayBuffer(64);
    new Uint8Array(binaryData).fill(0xfe);
    mockFetch.mockResolvedValueOnce(binaryResponse(binaryData));

    const result = await client.downloadArtifact("art-42");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/artifacts/art-42/download");
    expect(init.method).toBe("GET");
    expect(result).toBeInstanceOf(ArrayBuffer);
    expect(result.byteLength).toBe(64);
  });

  it("17. deleteArtifact — DELETE 204", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));

    const result = await client.deleteArtifact("art-42");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/artifacts/art-42");
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  // ─── API Keys ───

  it("18. listAPIKeys — GET list", async () => {
    const keys = [
      { id: "key-1", label: "CI pipeline", scope: "read", is_active: true },
      { id: "key-2", label: "Backup", scope: "admin", is_active: false },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(keys));

    const result = await client.listAPIKeys();

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/api-keys");
    expect(init.method).toBe("GET");
    expect(result).toEqual(keys);
  });

  it("19. createAPIKey — POST with label", async () => {
    const key = {
      id: "key-3",
      label: "Automation",
      scope: "write",
      is_active: true,
      key: "sk-live-abc123",
      warning: "Store this key securely. It will not be shown again.",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(key, 201));

    const result = await client.createAPIKey({
      label: "Automation",
      scope: "write",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/api-keys");
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.label).toBe("Automation");
    expect(body.scope).toBe("write");
    expect(result).toEqual(key);
  });

  it("20. revokeAPIKey — DELETE", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));

    const result = await client.revokeAPIKey("key-2");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/api-keys/key-2");
    expect(init.method).toBe("DELETE");
    expect(result).toBeUndefined();
  });

  // ─── Reports ───

  it("21. generateReport — POST returns ArrayBuffer (PDF)", async () => {
    const pdfData = new ArrayBuffer(128);
    new Uint8Array(pdfData).set([0x25, 0x50, 0x44, 0x46]); // %PDF magic bytes
    mockFetch.mockResolvedValueOnce(binaryResponse(pdfData));

    const result = await client.generateReport("asmt-1");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/report");
    expect(init.method).toBe("POST");
    expect(result).toBeInstanceOf(ArrayBuffer);
    const magic = new Uint8Array(result).slice(0, 4);
    expect(Array.from(magic)).toEqual([0x25, 0x50, 0x44, 0x46]);
  });

  it("21b. getReportStream — POST returns ReadableStream", async () => {
    const chunks = [new Uint8Array([0x25, 0x50, 0x44, 0x46])];
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const c of chunks) controller.enqueue(c);
        controller.close();
      },
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "Content-Type": "application/pdf" }),
      body: stream,
    } as unknown as Response);

    const result = await client.getReportStream("asmt-1", "pdf");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/report");
    expect(url).toContain("format=pdf");
    expect(init.method).toBe("POST");
    expect(result).toBeInstanceOf(ReadableStream);
  });

  it("21c. getReportStream — throws when body is null", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      headers: new Headers({ "Content-Type": "application/pdf" }),
      body: null,
    } as unknown as Response);

    await expect(client.getReportStream("asmt-1")).rejects.toThrow(
      "Server returned no body for report stream",
    );
  });

  // ─── Audit ───

  it("22. getAuditLog — GET with params", async () => {
    const entries = [
      {
        id: "aud-1",
        action: "organisation.created",
        actor: "user@acme.de",
        resource_type: "organisation",
        resource_id: "org-1",
        timestamp: "2026-01-01T00:00:00Z",
      },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(entries));

    const result = await client.getAuditLog(50, 2);

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/audit");
    expect(url).toContain("limit=50");
    expect(url).toContain("page=2");
    expect(init.method).toBe("GET");
    expect(result).toEqual(entries);
  });

  it("22b. getAuditEntry — GET by ID", async () => {
    const entry = {
      id: "aud-99",
      action: "control.updated",
      actor: "auditor@acme.de",
      resource_type: "control",
      resource_id: "ctrl-1",
      timestamp: "2026-03-15T10:30:00Z",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(entry));

    const result = await client.getAuditEntry("aud-99");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/audit/aud-99");
    expect(init.method).toBe("GET");
    expect(result).toEqual(entry);
  });

  // ─── Health ───

  it("23. getHealth — public endpoint (no auth)", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ status: "ok" }));

    const result = await client.getHealth();

    expect(result.status).toBe("ok");
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toContain("/health");
    expect(url).not.toContain("/health/detail");
    expect(init.method).toBe("GET");
    // Public endpoint must NOT send Authorization header
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBeUndefined();
  });

  it("24. getHealthDetail — authenticated with detailed status", async () => {
    const health = { status: "ok", version: "0.1.0", db: "connected", redis: "connected" };
    mockFetch.mockResolvedValueOnce(jsonResponse(health));

    const result = await client.getHealthDetail();

    const { url, init } = lastFetchCall();
    expect(url).toContain("/health/detail");
    expect(init.method).toBe("GET");
    // Verify that auth header is present
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe(`Bearer ${API_KEY}`);
    expect(result.version).toBe("0.1.0");
    expect(result.db).toBe("connected");
    expect(result.redis).toBe("connected");
    expect(result.status).toBe("ok");
  });

  // ─── Error handling ───

  it("25. 404 error — throws OpenSecStackError", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: "Organisation not found" }, 404),
    );

    await expect(client.getOrganisation("nonexistent")).rejects.toThrow(
      OpenSecStackError,
    );

    try {
      mockFetch.mockResolvedValueOnce(
        jsonResponse({ error: "Organisation not found" }, 404),
      );
      await client.getOrganisation("nonexistent");
    } catch (err) {
      expect(err).toBeInstanceOf(OpenSecStackError);
      expect((err as OpenSecStackError).statusCode).toBe(404);
      expect((err as OpenSecStackError).message).toBe(
        "Organisation not found",
      );
    }
  });

  it("26. 400 validation error — throws with message", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse(
        { error: "Validation failed: name is required", code: "VALIDATION_ERROR" },
        400,
      ),
    );

    await expect(
      client.createOrganisation({
        name: "",
        industry: "technology",
        country: "DE",
      }),
    ).rejects.toThrow(OpenSecStackError);

    mockFetch.mockResolvedValueOnce(
      jsonResponse(
        { error: "Validation failed: name is required", code: "VALIDATION_ERROR" },
        400,
      ),
    );

    try {
      await client.createOrganisation({
        name: "",
        industry: "technology",
        country: "DE",
      });
    } catch (err) {
      expect(err).toBeInstanceOf(OpenSecStackError);
      expect((err as OpenSecStackError).statusCode).toBe(400);
      expect((err as OpenSecStackError).message).toBe(
        "Validation failed: name is required",
      );
      expect((err as OpenSecStackError).code).toBe("VALIDATION_ERROR");
    }
  });

  // ─── Additional coverage ───

  it("sends Authorization header on all requests", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    await client.getOrganisations();

    const { init } = lastFetchCall();
    const headers = init.headers as Record<string, string>;
    expect(headers["Authorization"]).toBe("Bearer test-api-key-123");
  });

  it("omits undefined query params", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse([]));

    await client.getOrganisations({});

    const { url } = lastFetchCall();
    // No query params should be set for empty options
    const parsed = new URL(url);
    expect(parsed.searchParams.has("page")).toBe(false);
    expect(parsed.searchParams.has("per_page")).toBe(false);
  });

  // ─── getControls (non-paginated) ───

  it("getControls — GET without filters", async () => {
    const controls = [
      { measure_ref: "art21_a", status: "compliant" },
      { measure_ref: "art21_b", status: "partial" },
    ];
    mockFetch.mockResolvedValueOnce(jsonResponse(controls));

    const result = await client.getControls("asmt-1");

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/controls");
    expect(init.method).toBe("GET");
    const parsed = new URL(url);
    expect(parsed.searchParams.has("status")).toBe(false);
    expect(parsed.searchParams.has("nist_category")).toBe(false);
    expect(result).toHaveLength(2);
  });

  // ─── uploadArtifact ───

  it("uploadArtifact — POST with FormData", async () => {
    const artifact = {
      id: "art-1",
      artifact_type: "evidence",
      filename: "report.pdf",
    };
    mockFetch.mockResolvedValueOnce(jsonResponse(artifact));

    const blob = new Blob(["pdf-content"], { type: "application/pdf" });
    const result = await client.uploadArtifact("asmt-1", blob, "evidence", {
      control_id: "ctrl-1",
      description: "Test evidence",
    });

    const { url, init } = lastFetchCall();
    expect(url).toContain("/api/v1/assessments/asmt-1/artifacts");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
    const headers = init.headers as Record<string, string>;
    expect(headers["Content-Type"]).toBeUndefined();
    expect(result).toEqual(artifact);
  });
});
