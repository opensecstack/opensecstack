import { apiClient } from "./client";

export interface ApiKey {
  id: number;
  name: string;
  key_prefix: string;
  created_at: string;
  last_used_at: string | null;
}

export interface ApiKeyCreateResponse {
  id: number;
  name: string;
  key: string;
  created_at: string;
}

export interface ApiKeyListResponse {
  keys: ApiKey[];
}

export async function listAPIKeys(): Promise<ApiKeyListResponse> {
  const res = await apiClient.get<ApiKeyListResponse>("/api/v1/me/api-keys");
  return res.data;
}

export async function createAPIKey(name: string): Promise<ApiKeyCreateResponse> {
  const res = await apiClient.post<ApiKeyCreateResponse>("/api/v1/me/api-keys", { name });
  return res.data;
}

export async function deleteAPIKey(id: number): Promise<void> {
  await apiClient.delete(`/api/v1/me/api-keys/${id}`);
}
