import { apiClient } from "./client";

export interface AuditEntry {
  id: string;
  action: string;
  target_type: string;
  target_id: string;
  note: string;
  created_at: string;
  actor_username: string;
}

export async function listAuditLog(limit = 50, offset = 0): Promise<{ entries: AuditEntry[]; count: number }> {
  const r = await apiClient.get("/api/v1/admin/audit-log", { params: { limit, offset } });
  return r.data;
}
