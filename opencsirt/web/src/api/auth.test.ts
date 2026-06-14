import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import axios from "axios";

// We test the thin wrapper functions, not the axios internals.
// vi.mock replaces apiClient so no real HTTP is made.
vi.mock("./client", () => ({
  apiClient: {
    post: vi.fn(),
    get: vi.fn(),
    interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
  },
}));

import { login } from "./auth";
import { apiClient } from "./client";

const mockPost = vi.mocked(apiClient.post);

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.resetAllMocks();
});

describe("login()", () => {
  it("returns the LoginResponse on success", async () => {
    const fakeResponse = {
      data: {
        token: "eyJ.test.token",
        expires_at: "2026-01-01T00:00:00Z",
        role: "analyst",
        sub: "alice",
      },
    };
    mockPost.mockResolvedValueOnce(fakeResponse);

    const result = await login("alice", "secret");

    expect(mockPost).toHaveBeenCalledWith("/api/v1/auth/login", {
      username: "alice",
      password: "secret",
    });
    expect(result.token).toBe("eyJ.test.token");
    expect(result.role).toBe("analyst");
    expect(result.sub).toBe("alice");
  });

  it("propagates non-2xx errors without swallowing them", async () => {
    const err = Object.assign(new Error("Request failed with status code 401"), {
      response: { status: 401, data: { detail: "invalid credentials" } },
    });
    mockPost.mockRejectedValueOnce(err);

    await expect(login("bad-user", "wrong-pass")).rejects.toThrow("401");
  });

  it("propagates network-level errors (no response)", async () => {
    mockPost.mockRejectedValueOnce(new Error("Network Error"));

    await expect(login("alice", "secret")).rejects.toThrow("Network Error");
  });
});
