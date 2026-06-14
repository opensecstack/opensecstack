import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";
import { createRule, deleteRule, listRules } from "./rules";

const okResponse = <T>(data: T) =>
  ({
    data,
    status: 200,
    statusText: "OK",
    headers: {},
    config: {} as never,
  }) as const;

describe("api/rules", () => {
  afterEach(() => vi.restoreAllMocks());

  it("listRules forwards limit/type and unwraps the rules array", async () => {
    const get = vi.spyOn(apiClient, "get").mockResolvedValueOnce(
      okResponse({
        rules: [
          {
            id: "11111111-1111-1111-1111-111111111111",
            type: "blocklist",
            cidr: "203.0.113.7/32",
            ttl_seconds: 3600,
            source: "operator",
            created_at: "2026-05-09T10:00:00Z",
            expires_at: "2026-05-09T11:00:00Z",
          },
        ],
        count: 1,
      }),
    );

    const out = await listRules({ limit: 50, type: "blocklist" });

    expect(get).toHaveBeenCalledWith("/api/v1/rules", {
      params: { limit: 50, type: "blocklist" },
    });
    expect(out.count).toBe(1);
    expect(out.rules[0].cidr).toBe("203.0.113.7/32");
  });

  it("createRule POSTs the body", async () => {
    const post = vi.spyOn(apiClient, "post").mockResolvedValueOnce(
      okResponse({
        id: "22222222-2222-2222-2222-222222222222",
        type: "ratelimit" as const,
        cidr: "198.51.100.7/32",
        pps: 100,
        ttl_seconds: 600,
        source: "operator",
        created_at: "2026-05-10T00:00:00Z",
        expires_at: "2026-05-10T00:10:00Z",
      }),
    );

    const out = await createRule({
      type: "ratelimit",
      cidr: "198.51.100.7/32",
      pps: 100,
      ttl_seconds: 600,
    });

    expect(post).toHaveBeenCalledWith(
      "/api/v1/rules",
      expect.objectContaining({ type: "ratelimit", pps: 100 }),
    );
    expect(out.id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("deleteRule DELETEs by id", async () => {
    const del = vi.spyOn(apiClient, "delete").mockResolvedValueOnce(okResponse(undefined));
    await deleteRule("33333333-3333-3333-3333-333333333333");
    expect(del).toHaveBeenCalledWith("/api/v1/rules/33333333-3333-3333-3333-333333333333");
  });
});
