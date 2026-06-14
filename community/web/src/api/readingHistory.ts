import { apiClient } from "./client";
import type { Post } from "./posts";

export interface HistoryPost extends Post {
  read_at: string;
}

export interface ReadingHistoryResponse {
  posts: HistoryPost[];
  count: number;
}

export async function recordRead(postId: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/read`);
}

export async function fetchReadingHistory(
  page = 1,
  limit = 20,
): Promise<ReadingHistoryResponse> {
  const res = await apiClient.get<ReadingHistoryResponse>("/api/v1/me/history", {
    params: { page, limit },
  });
  return res.data;
}
