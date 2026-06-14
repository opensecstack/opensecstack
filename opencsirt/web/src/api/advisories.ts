import { apiClient } from "./client";

export type Tlp = "clear" | "green" | "amber" | "red";

export type AdvisoryState = "draft" | "published" | "withdrawn";

export interface Advisory {
  id: string;
  incident_id?: string;
  title: string;
  summary?: string;
  csaf_id: string;
  tlp: Tlp;
  state: AdvisoryState;
  version: number;
  published_at: string | null;
  withdrawn_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface AdvisoryListResponse {
  advisories: Advisory[];
  count: number;
}

export async function listAdvisories(limit = 50, offset = 0): Promise<AdvisoryListResponse> {
  const res = await apiClient.get<AdvisoryListResponse>("/api/v1/advisories", {
    params: { limit, offset },
  });
  return res.data;
}

export async function getAdvisoryCsaf(id: string): Promise<unknown> {
  const res = await apiClient.get(`/api/v1/advisories/${id}/csaf`);
  return res.data;
}

export async function publishAdvisory(id: string): Promise<Advisory> {
  const res = await apiClient.post<Advisory>(`/api/v1/advisories/${id}/publish`);
  return res.data;
}

export async function withdrawAdvisory(id: string): Promise<Advisory> {
  const res = await apiClient.post<Advisory>(`/api/v1/advisories/${id}/withdraw`);
  return res.data;
}
