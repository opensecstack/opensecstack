import { describe, it, expect } from "vitest";
import { apiClient } from "@/api/client";

describe("apiClient", () => {
  it("is created with a baseURL", () => {
    expect(apiClient).toBeDefined();
    expect(apiClient.defaults.baseURL).toBeTruthy();
  });

  it("registers request and response interceptors", () => {
    // The handler arrays exist on AxiosInstance with a `handlers` array.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- internal axios shape
    const req: any[] = (apiClient.interceptors.request as any).handlers;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- internal axios shape
    const res: any[] = (apiClient.interceptors.response as any).handlers;
    expect(req.length).toBeGreaterThan(0);
    expect(res.length).toBeGreaterThan(0);
  });
});
