import { apiClient } from "./client";

export async function followTag(slug: string): Promise<void> {
  await apiClient.post(`/api/v1/tags/${slug}/follow`);
}

export async function unfollowTag(slug: string): Promise<void> {
  await apiClient.delete(`/api/v1/tags/${slug}/follow`);
}

export async function getTagFollowStatus(slug: string): Promise<{ following: boolean }> {
  const r = await apiClient.get(`/api/v1/tags/${slug}/follow`);
  return r.data;
}

export async function listFollowingTagsFeed(limit = 20, offset = 0): Promise<{ posts: unknown[]; count: number }> {
  const r = await apiClient.get("/api/v1/feed/following-tags", { params: { limit, offset } });
  return r.data;
}
