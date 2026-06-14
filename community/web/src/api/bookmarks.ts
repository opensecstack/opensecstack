import { apiClient } from "./client";
import type { PostListResponse } from "./posts";

export async function bookmarkPost(postId: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/bookmark`);
}

export async function unbookmarkPost(postId: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${postId}/bookmark`);
}

export async function getBookmarkStatus(postId: string): Promise<{ bookmarked: boolean }> {
  const res = await apiClient.get<{ bookmarked: boolean }>(`/api/v1/posts/${postId}/bookmark-status`);
  return res.data;
}

export async function listMyBookmarks(limit?: number, offset?: number): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>("/api/v1/me/bookmarks", {
    params: { limit, offset },
  });
  return res.data;
}
