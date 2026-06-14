import { apiClient } from "./client";

export interface HealthResponse {
  status: string;
  db: boolean;
  version: string;
  uptime_seconds: number;
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await apiClient.get<HealthResponse>("/api/v1/health");
  return res.data;
}
