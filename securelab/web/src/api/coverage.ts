import { apiClient } from "./client";

export interface CoverageEntry {
  technique_id: string;
  technique_name: string;
  tactic: string;
  scenario_count: number;
  last_detected_at: string | null;
  detection_rate: number;
}

export interface CoverageResponse {
  entries: CoverageEntry[];
}

export async function getCoverage(): Promise<CoverageResponse> {
  const res = await apiClient.get<CoverageResponse>("/api/v1/coverage");
  return res.data;
}
