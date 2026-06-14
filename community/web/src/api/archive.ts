import { apiClient } from "./client";

export async function archivePost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/archive`);
}

export async function unarchivePost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}/archive`);
}
