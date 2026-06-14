import { apiClient } from "./client";

export interface Mitigation {
  id: string;
  rule_id: string;
  started_at: string;
  ended_at: string | null;
  packets_dropped: number;
  bytes_dropped: number;
  src_ip: string;
  emitted: boolean;
}

export interface MitigationListResponse {
  mitigations: Mitigation[];
  count: number;
}

export async function listMitigations(limit = 100): Promise<MitigationListResponse> {
  const res = await apiClient.get<MitigationListResponse>("/api/v1/mitigations", {
    params: { limit },
  });
  return res.data;
}
