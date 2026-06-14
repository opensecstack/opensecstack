import { apiClient } from "./client";

export async function lockPost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/lock`);
}

export async function unlockPost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/unlock`);
}
