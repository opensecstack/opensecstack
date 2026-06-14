import { apiClient } from "./client";

export async function pinPost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/pin`);
}

export async function unpinPost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}/pin`);
}
