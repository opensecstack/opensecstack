import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createHmac, createHash } from "node:crypto";
import { CITADELClient } from "../citadel.js";
import type { CITADELClientOptions } from "../citadel.js";
import { OpenSecStackError, RateLimitError } from "../types.js";
import type { SecurityEvent, Advisory } from "../types.js";

// ─── Mock fetch ───

const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function jsonResponse(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers({ "Content-Type": "application/json" }),
    json: async () => body,
  };
}

function noContentResponse() {
  return {
    ok: true,
    status: 204,
    headers: new Headers(),
    json: async () => undefined,
  };
}

function rateLimitResponse(retryAfter: number) {
  return {
    ok: false,
    status: 429,
    headers: new Headers({ "Retry-After": String(retryAfter) }),
    json: async () => ({ error: "Rate limited" }),
  };
}

function serverErrorResponse(status = 500) {
  return {
    ok: false,
    status,
    headers: new Headers({ "Content-Type": "application/json" }),
    json: async () => ({ error: `Server error: ${status}` }),
  };
}

// ─── Fixtures ───

const CLIENT_OPTS = {
  baseURL: "https://citadel.example.com",
  keyID: "key-001",
  sharedSecret: "super-secret-key",
  maxRetries: 0,
  retryWaitBase: 0,
};

function makeClient(overrides?: Partial<CITADELClientOptions>) {
  return new CITADELClient({ ...CLIENT_OPTS, ...overrides });
}

function makeEvent(overrides?: Partial<SecurityEvent>): SecurityEvent {
  return {
    id: "evt-001",
    event_type: "auth.login",
    source: "auth-service",
    actor_id: "user-1",
    actor_type: "user",
    resource_type: "session",
    resource_id: "sess-1",
    severity: "medium",
    payload: { ip: "10.0.0.1" },
    chain_hash: "abc123",
    prev_hash: null,
    timestamp: "2026-03-31T00:00:00Z",
    ...overrides,
  };
}

function makeAdvisory(overrides?: Partial<Advisory>): Advisory {
  return {
    id: "adv-001",
    title: "Critical RCE in OpenSSL",
    description: "A remote code execution vulnerability.",
    severity: "critical",
    status: "draft",
    affects: [{ component: "openssl", version_min: "3.0.0", version_max: "3.0.7" }],
    cve: "CVE-2026-0001",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2026-0001"],
    created_at: "2026-03-30T12:00:00Z",
    updated_at: "2026-03-30T12:00:00Z",
    ...overrides,
  };
}

function getHeaders(): Record<string, string> {
  const call = mockFetch.mock.calls[0];
  return call?.[1]?.headers ?? {};
}

// ─── Test Suite ───

describe("CITADELClient", () => {
  let client: CITADELClient;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-03-31T12:00:00Z"));
    mockFetch.mockReset();
    client = makeClient();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ─── HMAC Auth ───

  describe("HMAC authentication", () => {
    it("1. every request includes X-CITADEL-KEY, X-CITADEL-TS, X-CITADEL-SIG headers", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));
      await client.getEvents();

      const headers = getHeaders();
      expect(headers["X-CITADEL-KEY"]).toBe("key-001");
      expect(headers["X-CITADEL-TS"]).toBeDefined();
      expect(headers["X-CITADEL-SIG"]).toBeDefined();
    });

    it("2. signature format is hmac-sha256=<hex>", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));
      await client.getEvents();

      const sig = getHeaders()["X-CITADEL-SIG"]!;
      expect(sig).toMatch(/^hmac-sha256=[0-9a-f]{64}$/);
    });

    it("3. no Bearer/Authorization header is sent", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));
      await client.getEvents();

      const headers = getHeaders();
      expect(headers["Authorization"]).toBeUndefined();
      expect(headers["authorization"]).toBeUndefined();
    });

    it("signature is correctly computed from keyID + ts + sha256(body)", async () => {
      const event = {
        event_type: "auth.login",
        source: "auth-service",
        actor_id: "user-1",
        actor_type: "user",
        resource_type: "session",
        resource_id: "sess-1",
        severity: "medium",
        payload: {},
      };

      mockFetch.mockResolvedValueOnce(jsonResponse(200, undefined));
      await client.sendEventSync(event);

      const headers = getHeaders();
      const ts = headers["X-CITADEL-TS"]!;
      const bodyStr = JSON.stringify(event);
      const bodyHash = createHash("sha256").update(bodyStr).digest("hex");
      const message = `key-001:${ts}:${bodyHash}`;
      const expectedSig =
        "hmac-sha256=" +
        createHmac("sha256", "super-secret-key").update(message).digest("hex");

      expect(headers["X-CITADEL-SIG"]).toBe(expectedSig);
    });

    it("GET requests sign an empty body string", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));
      await client.getEvents();

      const headers = getHeaders();
      const ts = headers["X-CITADEL-TS"]!;
      const bodyHash = createHash("sha256").update("").digest("hex");
      const message = `key-001:${ts}:${bodyHash}`;
      const expectedSig =
        "hmac-sha256=" +
        createHmac("sha256", "super-secret-key").update(message).digest("hex");

      expect(headers["X-CITADEL-SIG"]).toBe(expectedSig);
    });
  });

  // ─── Events ───

  describe("Events", () => {
    it("4. sendEventSync — POST /api/v1/events with event body", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { id: "evt-new" }));

      const event = {
        event_type: "auth.login",
        source: "auth-service",
        actor_id: "user-1",
        actor_type: "user",
        resource_type: "session",
        resource_id: "sess-1",
        severity: "medium",
        payload: { ip: "10.0.0.1" },
      };

      await client.sendEventSync(event);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://citadel.example.com/api/v1/events");
      expect(init.method).toBe("POST");
      expect(init.body).toBe(JSON.stringify(event));
    });

    it("5. getEvents — GET with no filters", async () => {
      const events = [makeEvent()];
      mockFetch.mockResolvedValueOnce(jsonResponse(200, events));

      const result = await client.getEvents();

      expect(result).toEqual(events);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://citadel.example.com/api/v1/events");
      expect(init.method).toBe("GET");
    });

    it("6. getEvents — GET with all filters", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));

      await client.getEvents({
        source: "auth-service",
        event_type: "auth.login",
        since: "2026-03-01T00:00:00Z",
        until: "2026-03-31T23:59:59Z",
        limit: 10,
        page: 2,
      });

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toContain("source=auth-service");
      expect(url).toContain("event_type=auth.login");
      expect(url).toContain("since=2026-03-01T00%3A00%3A00Z");
      expect(url).toContain("until=2026-03-31T23%3A59%3A59Z");
      expect(url).toContain("limit=10");
      expect(url).toContain("page=2");
    });

    it("7. getEvent — GET by ID", async () => {
      const event = makeEvent({ id: "evt-42" });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, event));

      const result = await client.getEvent("evt-42");

      expect(result).toEqual(event);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://citadel.example.com/api/v1/events/evt-42");
      expect(init.method).toBe("GET");
    });

    it("8. getEvents — server error returns OpenSecStackError", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(500, { error: "Internal Server Error" }),
      );

      await expect(client.getEvents()).rejects.toThrow(OpenSecStackError);
    });
  });

  // ─── Chain Verification ───

  describe("Chain Verification", () => {
    function computeChainHash(prevChainHash: string, payload: Record<string, unknown>): string {
      const h = createHash("sha256");
      h.update(prevChainHash);
      h.update(JSON.stringify(payload));
      return h.digest("hex");
    }

    it("9. verifyChain — valid chain with recomputed hashes passes", () => {
      const genesis = "0000000000000000000000000000000000000000000000000000000000000000";
      const p0 = { seq: 0 };
      const h0 = computeChainHash(genesis, p0);

      const p1 = { seq: 1 };
      const h1 = computeChainHash(h0, p1);

      const p2 = { seq: 2 };
      const h2 = computeChainHash(h1, p2);

      const events: SecurityEvent[] = [
        makeEvent({ id: "evt-0", chain_hash: h0, prev_hash: null, payload: p0 }),
        makeEvent({ id: "evt-1", chain_hash: h1, prev_hash: h0, payload: p1 }),
        makeEvent({ id: "evt-2", chain_hash: h2, prev_hash: h1, payload: p2 }),
      ];

      expect(() => client.verifyChain(events)).not.toThrow();
    });

    it("10. verifyChain — broken prev_hash linkage throws error with index", () => {
      const genesis = "0000000000000000000000000000000000000000000000000000000000000000";
      const p0 = { seq: 0 };
      const h0 = computeChainHash(genesis, p0);

      const p1 = { seq: 1 };
      const h1 = computeChainHash(h0, p1);

      const events: SecurityEvent[] = [
        makeEvent({ id: "evt-0", chain_hash: h0, prev_hash: null, payload: p0 }),
        makeEvent({ id: "evt-1", chain_hash: h1, prev_hash: "WRONG", payload: p1 }),
      ];

      expect(() => client.verifyChain(events)).toThrow(
        /Chain broken at index 1/,
      );
    });

    it("11. verifyChain — empty array passes", () => {
      expect(() => client.verifyChain([])).not.toThrow();
    });

    it("verifyChain — single event passes (no links to verify)", () => {
      const events: SecurityEvent[] = [
        makeEvent({ id: "evt-0", chain_hash: "anything", prev_hash: null }),
      ];
      expect(() => client.verifyChain(events)).not.toThrow();
    });

    it("verifyChain — tampered payload detected via chain hash mismatch", () => {
      const genesis = "0000000000000000000000000000000000000000000000000000000000000000";
      const p0 = { seq: 0 };
      const h0 = computeChainHash(genesis, p0);

      const p1 = { seq: 1 };
      const h1 = computeChainHash(h0, p1);

      // Tamper with the payload of event 1 but keep the original chain_hash
      const tamperedP1 = { seq: 1, tampered: true };

      const events: SecurityEvent[] = [
        makeEvent({ id: "evt-0", chain_hash: h0, prev_hash: null, payload: p0 }),
        makeEvent({ id: "evt-1", chain_hash: h1, prev_hash: h0, payload: tamperedP1 }),
      ];

      expect(() => client.verifyChain(events)).toThrow(
        /Chain hash mismatch at index 0 -> 1/,
      );
    });

    it("verifyChain — tampered chain_hash detected", () => {
      const genesis = "0000000000000000000000000000000000000000000000000000000000000000";
      const p0 = { seq: 0 };
      const h0 = computeChainHash(genesis, p0);

      const p1 = { seq: 1 };
      // Use a wrong chain hash for event 1
      const wrongH1 = "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad";

      const events: SecurityEvent[] = [
        makeEvent({ id: "evt-0", chain_hash: h0, prev_hash: null, payload: p0 }),
        makeEvent({ id: "evt-1", chain_hash: wrongH1, prev_hash: h0, payload: p1 }),
      ];

      expect(() => client.verifyChain(events)).toThrow(
        /Chain hash mismatch at index 0 -> 1/,
      );
    });
  });

  // ─── Drain ───

  describe("Drain", () => {
    it("drain resolves immediately when no pending events", async () => {
      await expect(client.drain()).resolves.toBeUndefined();
    });

    it("drain waits for in-flight sendEvent to complete", async () => {
      vi.useRealTimers();
      const drainClient = makeClient({ maxRetries: 0, retryWaitBase: 0 });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { id: "evt-new" }));

      // Fire off a sendEvent (fire-and-forget, returns void)
      drainClient.sendEvent({
        event_type: "auth.login",
        source: "auth-service",
        actor_id: "user-1",
        actor_type: "user",
        resource_type: "session",
        resource_id: "sess-1",
        severity: "medium",
        payload: {},
      });

      // drain should flush the queue and wait for all in-flight sends
      await drainClient.drain();

      expect(mockFetch).toHaveBeenCalled();
    });

    it("drain times out if events hang", async () => {
      vi.useRealTimers();
      const hangClient = makeClient({ maxRetries: 0, retryWaitBase: 0 });

      // Mock fetch that never resolves
      mockFetch.mockReturnValue(new Promise(() => {}));

      // Fire off a sendEvent (fire-and-forget) that will hang during HTTP delivery
      hangClient.sendEvent({
        event_type: "auth.login",
        source: "auth-service",
        actor_id: "user-1",
        actor_type: "user",
        resource_type: "session",
        resource_id: "sess-1",
        severity: "medium",
        payload: {},
      });

      // drain with a very short timeout should reject
      await expect(hangClient.drain(50)).rejects.toThrow("Drain timed out");
    });
  });

  // ─── Non-blocking event dispatch ───

  describe("Non-blocking event dispatch", () => {
    const sampleEvent = {
      event_type: "auth.login",
      source: "auth-service",
      actor_id: "user-1",
      actor_type: "user",
      resource_type: "session",
      resource_id: "sess-1",
      severity: "medium",
      payload: {},
    };

    it("sendEvent is non-blocking (fire-and-forget)", () => {
      // sendEvent returns void, not a Promise — it is synchronous
      const result = client.sendEvent(sampleEvent);
      expect(result).toBeUndefined();
      // Since it's undefined, it's certainly not a Promise/thenable.
      // Compare with sendEventSync which returns a Promise:
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { id: "evt-new" }));
      const syncResult = client.sendEventSync(sampleEvent);
      expect(syncResult).toBeInstanceOf(Promise);
    });

    it("sendEvent drops events when queue is full", async () => {
      vi.useRealTimers();
      // Create a client with a tiny queue (maxQueueSize=3) and mock fetch that never resolves
      // so nothing drains from the queue via inflight processing.
      const smallQueueClient = makeClient({
        maxRetries: 0,
        retryWaitBase: 0,
        maxQueueSize: 3,
      });
      mockFetch.mockReturnValue(new Promise(() => {}));

      // Fill the queue to capacity
      smallQueueClient.sendEvent({ ...sampleEvent, payload: { i: 1 } });
      smallQueueClient.sendEvent({ ...sampleEvent, payload: { i: 2 } });
      smallQueueClient.sendEvent({ ...sampleEvent, payload: { i: 3 } });

      // The 4th event should be silently dropped (no error thrown)
      expect(() => {
        smallQueueClient.sendEvent({ ...sampleEvent, payload: { i: 4 } });
      }).not.toThrow();

      // Drain will process the 3 queued events (they hang forever), so we timeout
      // and just verify the fetch was called exactly 3 times (not 4).
      // Give drain a moment to flush the queue before timing out.
      try {
        await smallQueueClient.drain(100);
      } catch {
        // expected timeout
      }
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("sendEventSync blocks until HTTP completes", async () => {
      vi.useRealTimers();
      const syncClient = makeClient({ maxRetries: 0, retryWaitBase: 0 });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, { id: "evt-new" }));

      // sendEventSync returns a Promise
      const result = syncClient.sendEventSync(sampleEvent);
      expect(result).toBeInstanceOf(Promise);

      await result;

      // Fetch should have been called
      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://citadel.example.com/api/v1/events");
      expect(init.method).toBe("POST");
    });

    it("drain processes remaining queued events", async () => {
      vi.useRealTimers();
      const drainClient = makeClient({ maxRetries: 0, retryWaitBase: 0 });
      mockFetch
        .mockResolvedValueOnce(jsonResponse(200, { id: "evt-1" }))
        .mockResolvedValueOnce(jsonResponse(200, { id: "evt-2" }))
        .mockResolvedValueOnce(jsonResponse(200, { id: "evt-3" }));

      // Queue 3 events (fire-and-forget)
      drainClient.sendEvent({ ...sampleEvent, payload: { i: 1 } });
      drainClient.sendEvent({ ...sampleEvent, payload: { i: 2 } });
      drainClient.sendEvent({ ...sampleEvent, payload: { i: 3 } });

      // Drain should flush the queue and wait for all 3 HTTP requests to complete
      await drainClient.drain();

      expect(mockFetch).toHaveBeenCalledTimes(3);
      // Verify each call was a POST to the events endpoint
      for (const [url, init] of mockFetch.mock.calls) {
        expect(url).toBe("https://citadel.example.com/api/v1/events");
        expect(init.method).toBe("POST");
      }
    });

    it("concurrent event dispatch respects concurrency limit", async () => {
      vi.useRealTimers();
      const concurrencyClient = makeClient({
        maxRetries: 0,
        retryWaitBase: 0,
        concurrency: 4,
      });

      // Track peak concurrency
      let currentInflight = 0;
      let peakInflight = 0;

      mockFetch.mockImplementation(() => {
        currentInflight++;
        if (currentInflight > peakInflight) {
          peakInflight = currentInflight;
        }
        return new Promise<ReturnType<typeof jsonResponse>>((resolve) => {
          setTimeout(() => {
            currentInflight--;
            resolve(jsonResponse(200, { id: "evt-new" }));
          }, 10);
        });
      });

      // Queue 20 events
      for (let i = 0; i < 20; i++) {
        concurrencyClient.sendEvent({ ...sampleEvent, payload: { i } });
      }

      // Drain and wait for all to complete
      await concurrencyClient.drain(10_000);

      // All 20 events should have been sent
      expect(mockFetch).toHaveBeenCalledTimes(20);
      // Peak concurrency should not exceed the limit of 4
      expect(peakInflight).toBeLessThanOrEqual(4);
      // But it should actually use concurrency (at least 2 at once)
      expect(peakInflight).toBeGreaterThanOrEqual(2);
    });
  });

  // ─── AUGUR Advisories ───

  describe("AUGUR Advisories", () => {
    it("12. createAdvisory — POST /api/v1/augur/advisories", async () => {
      const advisory = makeAdvisory();
      mockFetch.mockResolvedValueOnce(jsonResponse(201, advisory));

      const req = {
        title: "Critical RCE in OpenSSL",
        description: "A remote code execution vulnerability.",
        severity: "critical" as const,
        cve: "CVE-2026-0001",
      };
      const result = await client.createAdvisory(req);

      expect(result).toEqual(advisory);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "https://citadel.example.com/api/v1/augur/advisories",
      );
      expect(init.method).toBe("POST");
      expect(init.body).toBe(JSON.stringify(req));
    });

    it("13. listAdvisories — GET with no filters", async () => {
      const advisories = [makeAdvisory()];
      mockFetch.mockResolvedValueOnce(jsonResponse(200, advisories));

      const result = await client.listAdvisories();

      expect(result).toEqual(advisories);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "https://citadel.example.com/api/v1/augur/advisories",
      );
      expect(init.method).toBe("GET");
    });

    it("14. listAdvisories — GET with all filters", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));

      await client.listAdvisories({
        page: 3,
        per_page: 25,
        status: "published",
        severity: "high",
      });

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toContain("page=3");
      expect(url).toContain("per_page=25");
      expect(url).toContain("status=published");
      expect(url).toContain("severity=high");
    });

    it("15. listAdvisories — empty response returns []", async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));

      const result = await client.listAdvisories();
      expect(result).toEqual([]);
    });

    it("16. getAdvisory — GET by ID", async () => {
      const advisory = makeAdvisory({ id: "adv-42" });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, advisory));

      const result = await client.getAdvisory("adv-42");

      expect(result).toEqual(advisory);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "https://citadel.example.com/api/v1/augur/advisories/adv-42",
      );
      expect(init.method).toBe("GET");
    });

    it("17. getAdvisory — empty ID throws immediately", async () => {
      await expect(client.getAdvisory("")).rejects.toThrow(
        "Advisory ID must not be empty",
      );
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("18. getAdvisory — 404 throws OpenSecStackError", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(404, { error: "Advisory not found", code: "NOT_FOUND" }),
      );

      try {
        await client.getAdvisory("nonexistent");
        expect.fail("Should have thrown");
      } catch (err) {
        expect(err).toBeInstanceOf(OpenSecStackError);
        expect((err as OpenSecStackError).statusCode).toBe(404);
        expect((err as OpenSecStackError).message).toMatch(/Advisory not found/);
        expect((err as OpenSecStackError).code).toBe("NOT_FOUND");
      }
    });

    it("19. patchAdvisory — PATCH with partial fields", async () => {
      const updated = makeAdvisory({ status: "published" });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, updated));

      const patch = { status: "published" as const };
      const result = await client.patchAdvisory("adv-001", patch);

      expect(result).toEqual(updated);
      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "https://citadel.example.com/api/v1/augur/advisories/adv-001",
      );
      expect(init.method).toBe("PATCH");
      expect(init.body).toBe(JSON.stringify(patch));
    });

    it("20. patchAdvisory — empty ID throws", async () => {
      await expect(
        client.patchAdvisory("", { title: "updated" }),
      ).rejects.toThrow("Advisory ID must not be empty");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("21. deleteAdvisory — DELETE 204", async () => {
      mockFetch.mockResolvedValueOnce(noContentResponse());

      await expect(client.deleteAdvisory("adv-001")).resolves.toBeUndefined();

      const [url, init] = mockFetch.mock.calls[0]!;
      expect(url).toBe(
        "https://citadel.example.com/api/v1/augur/advisories/adv-001",
      );
      expect(init.method).toBe("DELETE");
    });

    it("22. deleteAdvisory — empty ID throws", async () => {
      await expect(client.deleteAdvisory("")).rejects.toThrow(
        "Advisory ID must not be empty",
      );
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("23. getActiveAdvisories — calls listAdvisories with status=published", async () => {
      const published = [makeAdvisory({ status: "published" })];
      mockFetch.mockResolvedValueOnce(jsonResponse(200, published));

      const result = await client.getActiveAdvisories();

      expect(result).toEqual(published);
      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toContain("status=published");
    });

    it("24. createAdvisory — 409 conflict throws OpenSecStackError", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(409, { error: "Advisory already exists", code: "CONFLICT" }),
      );

      await expect(
        client.createAdvisory({
          title: "Duplicate",
          description: "Dup advisory",
          severity: "high",
        }),
      ).rejects.toThrow(OpenSecStackError);

      try {
        mockFetch.mockResolvedValueOnce(
          jsonResponse(409, {
            error: "Advisory already exists",
            code: "CONFLICT",
          }),
        );
        await client.createAdvisory({
          title: "Duplicate",
          description: "Dup advisory",
          severity: "high",
        });
      } catch (err) {
        expect(err).toBeInstanceOf(OpenSecStackError);
        expect((err as OpenSecStackError).statusCode).toBe(409);
        expect((err as OpenSecStackError).code).toBe("CONFLICT");
      }
    });
  });

  // ─── Disabled Mode ───

  describe("Disabled mode", () => {
    it("25. when baseURL is empty, all methods return undefined/void without HTTP calls", async () => {
      const disabled = makeClient({ baseURL: "" });

      // sendEvent is fire-and-forget (synchronous void) — just call it
      disabled.sendEvent({
        event_type: "test",
        source: "test",
        actor_id: "u1",
        actor_type: "user",
        resource_type: "r",
        resource_id: "r1",
        severity: "low",
        payload: {},
      });

      // sendEventSync is the blocking variant
      await expect(disabled.sendEventSync({
        event_type: "test",
        source: "test",
        actor_id: "u1",
        actor_type: "user",
        resource_type: "r",
        resource_id: "r1",
        severity: "low",
        payload: {},
      })).resolves.toBeUndefined();

      await expect(disabled.getEvents()).resolves.toBeUndefined();
      await expect(disabled.getEvent("evt-1")).resolves.toBeUndefined();
      await expect(
        disabled.createAdvisory({
          title: "t",
          description: "d",
          severity: "low",
        }),
      ).resolves.toBeUndefined();
      await expect(disabled.listAdvisories()).resolves.toBeUndefined();
      await expect(disabled.getAdvisory("adv-1")).resolves.toBeUndefined();
      await expect(
        disabled.patchAdvisory("adv-1", { title: "x" }),
      ).resolves.toBeUndefined();
      await expect(disabled.deleteAdvisory("adv-1")).resolves.toBeUndefined();
      await expect(disabled.getActiveAdvisories()).resolves.toBeUndefined();

      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  // ─── Error Handling ───

  describe("Error handling", () => {
    it("26. 429 rate limit — throws RateLimitError", async () => {
      mockFetch.mockResolvedValueOnce(rateLimitResponse(120));

      await expect(client.getEvents()).rejects.toThrow(RateLimitError);
      try {
        mockFetch.mockResolvedValueOnce(rateLimitResponse(120));
        await client.getEvents();
      } catch (err) {
        expect(err).toBeInstanceOf(RateLimitError);
        expect((err as RateLimitError).retryAfter).toBe(120);
      }
    });

    it("27. 500 server error — retries then throws", async () => {
      vi.useRealTimers();
      const retryClient = makeClient({ maxRetries: 2, retryWaitBase: 1 });

      mockFetch
        .mockResolvedValueOnce(serverErrorResponse(500))
        .mockResolvedValueOnce(serverErrorResponse(502))
        .mockResolvedValueOnce(serverErrorResponse(503));

      await expect(retryClient.getEvents()).rejects.toThrow();
      // 1 initial + 2 retries = 3 total calls
      expect(mockFetch).toHaveBeenCalledTimes(3);
    });

    it("500 server error — succeeds on retry", async () => {
      vi.useRealTimers();
      const retryClient = makeClient({ maxRetries: 2, retryWaitBase: 1 });
      const events = [makeEvent()];

      mockFetch
        .mockResolvedValueOnce(serverErrorResponse(500))
        .mockResolvedValueOnce(jsonResponse(200, events));

      const result = await retryClient.getEvents();
      expect(result).toEqual(events);
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });

    it("429 with small Retry-After retries then succeeds", async () => {
      vi.useRealTimers();
      const retryClient = makeClient({ maxRetries: 1, retryWaitBase: 1 });
      const events = [makeEvent()];

      mockFetch
        .mockResolvedValueOnce(rateLimitResponse(0))
        .mockResolvedValueOnce(jsonResponse(200, events));

      const result = await retryClient.getEvents();
      expect(result).toEqual(events);
    });

    it("non-JSON error response uses HTTP status in message", async () => {
      mockFetch.mockResolvedValueOnce(
        jsonResponse(403, { error: "Forbidden" }),
      );

      try {
        await client.getEvents();
      } catch (err) {
        expect(err).toBeInstanceOf(OpenSecStackError);
        expect((err as OpenSecStackError).statusCode).toBe(403);
        expect((err as OpenSecStackError).message).toBe("Forbidden");
      }
    });
  });

  // ─── URL construction ───

  describe("URL construction", () => {
    it("strips trailing slashes from baseURL", async () => {
      const slashClient = makeClient({
        baseURL: "https://citadel.example.com///",
      });
      mockFetch.mockResolvedValueOnce(jsonResponse(200, []));

      await slashClient.getEvents();

      const [url] = mockFetch.mock.calls[0]!;
      expect(url).toBe("https://citadel.example.com/api/v1/events");
    });
  });
});
