import { apiClient } from "./client";

export type IncidentStatus = "open" | "triaged" | "contained" | "closed";
export type Severity = "low" | "medium" | "high" | "critical";

export type IncidentSource = "irflow" | "manual" | "abuse_mailbox" | "peer_csirt";

export interface Incident {
  id: string;
  title: string;
  source: IncidentSource;
  severity: Severity;
  constituency_id: string | null;
  status: IncidentStatus;
  description?: string;
  created_at: string;
  closed_at?: string;
  metadata?: Record<string, unknown>;
}

export interface IncidentListResponse {
  incidents: Incident[];
  count: number;
}

export async function listIncidents(limit = 50, offset = 0): Promise<IncidentListResponse> {
  const res = await apiClient.get<IncidentListResponse>("/api/v1/incidents", {
    params: { limit, offset },
  });
  return res.data;
}

export async function getIncident(id: string): Promise<Incident> {
  const res = await apiClient.get<Incident>(`/api/v1/incidents/${id}`);
  return res.data;
}
