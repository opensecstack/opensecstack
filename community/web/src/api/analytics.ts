import { apiClient } from "./client";

export interface DayCount {
  date: string;
  count: number;
}

export interface PostAnalytics {
  total_views: number;
  days: DayCount[];
}

export async function getPostAnalytics(postId: string): Promise<PostAnalytics> {
  const res = await apiClient.get<PostAnalytics>(`/api/v1/posts/${postId}/analytics`);
  return res.data;
}
