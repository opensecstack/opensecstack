import axios from "axios";

// Empty default → same-origin (Vite proxy in dev, reverse proxy in prod).
const baseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

// Wire shape from internal/api/handlers/handlers.go:Health.Get.
// status is "ok" | "degraded"; the legacy "down" level is synthesised
// client-side when the request itself fails.
export interface Health {
  status: "ok" | "degraded";
  version: string;
  db_ping: boolean;
  dataplane_attached: boolean;
}

export async function fetchHealth(): Promise<Health> {
  const res = await axios.get<Health>(`${baseURL}/api/v1/health`, {
    timeout: 5000,
  });
  return res.data;
}

export type HealthLevel = "ok" | "degraded" | "down";

export function deriveOverall(h: Health | undefined, isError: boolean): HealthLevel {
  if (isError || !h) return "down";
  return h.status;
}
