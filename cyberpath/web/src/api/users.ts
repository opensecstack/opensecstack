import { apiClient } from "./client";
import type { AuthUser, AuthTokens } from "@/state/auth";

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
  user: AuthUser;
}

export interface UserProgressTrack {
  track_id: string;
  track_slug: string;
  track_version: string;
  started_at: string;
  completed_at: string | null;
  lessons_total: number;
  lessons_done: number;
  quiz_avg: number;
}

export interface UserProgress {
  user_id: string;
  tracks: UserProgressTrack[];
}

export interface Certification {
  id: string;
  track_id: string;
  track_slug: string;
  track_version: string;
  issued_at: string;
  expires_at: string | null;
  evidence_hash: string;
  citadel_ledger_id: string | null;
  signature: string;
  download_url: string;
}

export interface CertificationsResponse {
  user_id: string;
  certifications: Certification[];
}

export async function login(email: string, password: string): Promise<LoginResponse> {
  const res = await apiClient.post<LoginResponse>("/api/v1/auth/login", { email, password });
  return res.data;
}

export async function refreshTokens(refresh_token: string): Promise<AuthTokens> {
  const res = await apiClient.post<AuthTokens>("/api/v1/auth/refresh", { refresh_token });
  return res.data;
}

export async function getProgress(userId: string): Promise<UserProgress> {
  const res = await apiClient.get<UserProgress>(`/api/v1/users/${encodeURIComponent(userId)}/progress`);
  return res.data;
}

export async function getCertifications(userId: string): Promise<CertificationsResponse> {
  const res = await apiClient.get<CertificationsResponse>(
    `/api/v1/users/${encodeURIComponent(userId)}/certifications`,
  );
  return res.data;
}
