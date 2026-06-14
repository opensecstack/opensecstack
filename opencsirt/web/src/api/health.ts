import axios from "axios";

const baseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

export interface Health {
  status: "ok" | "degraded";
  db: boolean;
  advisory_service: boolean;
  uptime_seconds: number;
}

export type HealthLevel = "ok" | "degraded" | "down";

export async function fetchHealth(): Promise<Health> {
  const res = await axios.get<Health>(`${baseURL}/api/v1/health`, { timeout: 5000 });
  return res.data;
}

export function deriveOverall(h: Health | undefined, isError: boolean): HealthLevel {
  if (isError || !h) return "down";
  if (!h.db) return "down";
  if (!h.advisory_service) return "degraded";
  return h.status;
}
