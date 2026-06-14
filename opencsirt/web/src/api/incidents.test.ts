import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("./client", () => ({
  apiClient: {
    post: vi.fn(),
    get: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}));

import { listIncidents, getIncident, type Incident } from "./incidents";
import { apiClient } from "./client";

const mockGet = vi.mocked(apiClient.get);

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.resetAllMocks();
});

const sampleIncident: Incident = {
  id: "inc-001",
  title: "Ransomware detected",
  severity: "critical",
  constituency_id: "const-abc",
  status: "open",
  created_at: "2026-05-10T00:00:00Z",
};

describe("listIncidents()", () => {
  it("parses the response shape and returns incidents + count", async () => {
    mockGet.mockResolvedValueOnce({
      data: { incidents: [sampleIncident], count: 1 },
    });

    const result = await listIncidents();

    expect(mockGet).toHaveBeenCalledWith("/api/v1/incidents", {
      params: { limit: 50, offset: 0 },
    });
    expect(result.count).toBe(1);
    expect(result.incidents).toHaveLength(1);
    expect(result.incidents[0].id).toBe("inc-001");
    expect(result.incidents[0].severity).toBe("critical");
    expect(result.incidents[0].status).toBe("open");
  });

  it("accepts custom limit/offset and forwards them to the API", async () => {
    mockGet.mockResolvedValueOnce({ data: { incidents: [], count: 0 } });

    await listIncidents(10, 20);

    expect(mockGet).toHaveBeenCalledWith("/api/v1/incidents", {
      params: { limit: 10, offset: 20 },
    });
  });

  it("propagates non-2xx errors", async () => {
    const err = Object.assign(new Error("Request failed with status code 403"), {
      response: { status: 403 },
    });
    mockGet.mockRejectedValueOnce(err);

    await expect(listIncidents()).rejects.toThrow("403");
  });
});

describe("getIncident()", () => {
  it("resolves a single incident by id", async () => {
    mockGet.mockResolvedValueOnce({ data: sampleIncident });

    const result = await getIncident("inc-001");

    expect(mockGet).toHaveBeenCalledWith("/api/v1/incidents/inc-001");
    expect(result.id).toBe("inc-001");
    expect(result.title).toBe("Ransomware detected");
  });

  it("propagates 404 as an error", async () => {
    const err = Object.assign(new Error("Request failed with status code 404"), {
      response: { status: 404 },
    });
    mockGet.mockRejectedValueOnce(err);

    await expect(getIncident("missing")).rejects.toThrow("404");
  });
});
