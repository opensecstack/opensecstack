import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";
import { listMitigations } from "./mitigations";

describe("api/mitigations", () => {
  afterEach(() => vi.restoreAllMocks());

  it("hits /api/v1/mitigations with the requested limit", async () => {
    const get = vi.spyOn(apiClient, "get").mockResolvedValueOnce({
      data: { mitigations: [], count: 0 },
      status: 200,
      statusText: "OK",
      headers: {},
      config: {} as never,
    });

    const out = await listMitigations(50);

    expect(get).toHaveBeenCalledWith("/api/v1/mitigations", {
      params: { limit: 50 },
    });
    expect(out.count).toBe(0);
  });

  it("uses limit=100 by default", async () => {
    const get = vi.spyOn(apiClient, "get").mockResolvedValueOnce({
      data: { mitigations: [], count: 0 },
      status: 200,
      statusText: "OK",
      headers: {},
      config: {} as never,
    });

    await listMitigations();

    expect(get).toHaveBeenCalledWith(
      "/api/v1/mitigations",
      expect.objectContaining({ params: { limit: 100 } }),
    );
  });
});
