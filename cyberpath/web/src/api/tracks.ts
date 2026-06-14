import { apiClient } from "./client";

export interface Track {
  id: string;
  slug: string;
  title: string;
  audience: string;
  nis2_measures: string[];
  estimated_minutes: number;
  lab_required: boolean;
  cert_offered: boolean;
  track_version: string;
}

export interface TrackListResponse {
  tracks: Track[];
  total: number;
  page: number;
}

export interface TrackModuleSummary {
  id: string;
  order: number;
  title_en: string;
  title_sq?: string;
  lesson_count: number;
}

export interface TrackDetail {
  id: string;
  slug: string;
  title_sq: string;
  title_en: string;
  description_sq: string;
  description_en: string;
  track_version: string;
  modules: TrackModuleSummary[];
  labs: Array<{ id: string; title_en: string }>;
  cert_offered: boolean;
  cert_expires_after_days: number | null;
}

export interface TrackLessonSummary {
  id: string;
  order: number;
  title_en: string;
  title_sq?: string;
  has_quiz: boolean;
  has_lab: boolean;
}

export interface TrackModuleDetail {
  id: string;
  order: number;
  title_en: string;
  title_sq?: string;
  lessons: TrackLessonSummary[];
}

export interface TrackModulesResponse {
  modules: TrackModuleDetail[];
}

export async function listTracks(params?: {
  audience?: string;
  nis2_measure?: string;
  cert_offered?: boolean;
  limit?: number;
  page?: number;
}): Promise<TrackListResponse> {
  const res = await apiClient.get<TrackListResponse>("/api/v1/tracks", { params });
  return res.data;
}

export async function getTrack(idOrSlug: string): Promise<TrackDetail> {
  const res = await apiClient.get<TrackDetail>(`/api/v1/tracks/${encodeURIComponent(idOrSlug)}`);
  return res.data;
}

export async function getTrackModules(idOrSlug: string): Promise<TrackModulesResponse> {
  const res = await apiClient.get<TrackModulesResponse>(
    `/api/v1/tracks/${encodeURIComponent(idOrSlug)}/modules`,
  );
  return res.data;
}
