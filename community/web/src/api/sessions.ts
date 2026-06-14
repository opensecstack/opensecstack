import { apiClient } from "./client";

export interface Session {
  id: string;
  device_info: string;
  ip_address: string;
  created_at: string;
  last_seen_at: string;
  is_current: boolean;
}

export async function listSessions(): Promise<Session[]> {
  const res = await apiClient.get<Session[]>("/api/v1/me/sessions");
  return res.data;
}

export async function revokeSession(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/me/sessions/${id}`);
}

export async function revokeAllSessions(): Promise<void> {
  await apiClient.delete("/api/v1/me/sessions");
}
