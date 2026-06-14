import { apiClient } from "./client";

export interface ContextNote {
  id: string;
  body: string;
  author_username: string;
  created_at: string;
  updated_at: string;
}

export async function getContextNote(postId: string): Promise<{ note: ContextNote | null }> {
  const r = await apiClient.get(`/api/v1/posts/${postId}/context-note`);
  return r.data;
}

export async function upsertContextNote(postId: string, body: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/context-note`, { body });
}

export async function deleteContextNote(postId: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${postId}/context-note`);
}
