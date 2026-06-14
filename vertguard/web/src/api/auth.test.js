import { afterEach, describe, expect, it, vi } from "vitest";
import { apiClient } from "./client";
import { login } from "./auth";
describe("api/auth", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });
    it("POSTs credentials to /api/v1/auth/login and returns the access token", async () => {
        const post = vi.spyOn(apiClient, "post").mockResolvedValueOnce({
            data: {
                access_token: "jwt.aaa.bbb",
                token_type: "Bearer",
                expires_at: "2026-05-10T12:00:00Z",
                role: "operator",
                sub: "alice",
            },
            status: 200,
            statusText: "OK",
            headers: {},
            config: {},
        });
        const out = await login("alice", "hunter2");
        expect(post).toHaveBeenCalledWith("/api/v1/auth/login", {
            username: "alice",
            password: "hunter2",
        });
        expect(out.access_token).toBe("jwt.aaa.bbb");
        expect(out.role).toBe("operator");
    });
    it("propagates a rejected request as an error", async () => {
        vi.spyOn(apiClient, "post").mockRejectedValueOnce(new Error("401 invalid_creds"));
        await expect(login("alice", "wrong")).rejects.toThrow("invalid_creds");
    });
});
