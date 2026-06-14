import { z } from "zod";
import { getToken } from "./auth";

const Match = z.object({
  pattern_id: z.string(),
  category: z.string(),
  description: z.string(),
  atlas_technique: z.string().optional(),
  byte_range: z.tuple([z.number(), z.number()]),
  confidence: z.number(),
});

export const ScanResponse = z.object({
  scan_id: z.string(),
  classification: z.enum(["CLEAN", "SUSPICIOUS", "BLOCKED"]),
  confidence: z.number(),
  matches: z.array(Match),
  duration_ms: z.number(),
  worm_entry_id: z.string().nullable().optional(),
});
export type ScanResponse = z.infer<typeof ScanResponse>;

export const HealthResponse = z.object({
  status: z.string(),
  db: z.string(),
  version: z.string(),
  commit: z.string(),
  built: z.string(),
  modules: z.record(z.string()),
  integrations: z.record(z.string()),
});
export type HealthResponse = z.infer<typeof HealthResponse>;

// Empty default → same-origin requests, routed via Vite proxy in dev or
// reverse proxy in prod. Override with VITE_API_BASE_URL only if needed.
const baseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

async function call<T>(path: string, opts: RequestInit, schema: z.ZodType<T>): Promise<T> {
  const token = getToken();
  const headers = new Headers(opts.headers);
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const resp = await fetch(`${baseURL}${path}`, { ...opts, headers });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`${resp.status}: ${body}`);
  }
  return schema.parse(await resp.json());
}

export const api = {
  health: () => call("/api/v1/health", { method: "GET" }, HealthResponse),
  scan: (input: string, context = "default") =>
    call("/api/v1/prompt/scan", { method: "POST", body: JSON.stringify({ input, context }) }, ScanResponse),
  atlasCoverage: () =>
    call("/api/v1/threatfeed/atlas/coverage", { method: "GET" }, z.any()),
  iocs: () => call("/api/v1/threatfeed/iocs", { method: "GET" }, z.any()),
};
