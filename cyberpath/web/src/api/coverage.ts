import { apiClient } from "./client";

export interface CoverageEntry {
  measure: string;
  covered: boolean;
  tracks: Array<{
    track_id: string;
    track_slug: string;
    track_version: string;
    issued_at?: string;
    expires_at?: string | null;
  }>;
}

export interface CoverageResponse {
  user_id: string;
  as_of: string;
  coverage: CoverageEntry[];
}

export interface RecommendationItem {
  track_id: string;
  track_slug: string;
  title_en: string;
  title_sq?: string;
  audience: string;
  estimated_minutes: number;
  lab_required: boolean;
  certification: boolean;
  addresses_measures: string[];
  priority: "primary" | "secondary";
}

export interface RecommendResponse {
  gap: string;
  measure: string;
  recommendations: RecommendationItem[];
}

export async function getCoverage(userId: string): Promise<CoverageResponse> {
  const res = await apiClient.get<CoverageResponse>(`/api/v1/coverage/${encodeURIComponent(userId)}`);
  return res.data;
}

export async function recommend(
  gap: string,
  params?: { audience?: string; max_duration_min?: number },
): Promise<RecommendResponse> {
  const res = await apiClient.get<RecommendResponse>("/api/v1/cyberpath/recommend", {
    params: { gap, ...params },
  });
  return res.data;
}
