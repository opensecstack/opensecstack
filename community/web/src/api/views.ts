import { apiClient } from "./client";

export async function recordView(postId: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/view`);
}
