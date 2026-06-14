import { apiClient } from "./client";

export interface SeriesPost {
  id: string;
  title: string;
  slug: string;
  position: number;
}

export interface Series {
  id: string;
  title: string;
  slug: string;
  description: string;
  created_at: string;
  author_username: string;
  author_name: string;
  posts: SeriesPost[];
}

export interface MySeries {
  id: string;
  title: string;
  slug: string;
  description: string;
  created_at: string;
  post_count: number;
}

export async function createSeries(title: string, description: string): Promise<{ id: string; slug: string }> {
  const res = await apiClient.post<{ id: string; slug: string }>("/api/v1/series", { title, description });
  return res.data;
}

export async function getSeries(slug: string): Promise<Series> {
  const res = await apiClient.get<Series>(`/api/v1/series/${slug}`);
  return res.data;
}

export async function addPostToSeries(seriesId: string, postId: string, position: number): Promise<void> {
  await apiClient.post(`/api/v1/series/${seriesId}/posts`, { post_id: postId, position });
}

export async function removePostFromSeries(seriesId: string, postId: string): Promise<void> {
  await apiClient.delete(`/api/v1/series/${seriesId}/posts/${postId}`);
}

export async function listMySeries(): Promise<MySeries[]> {
  const res = await apiClient.get<MySeries[]>("/api/v1/me/series");
  return Array.isArray(res.data) ? res.data : [];
}

export interface SeriesNavPost {
  id: string;
  title: string;
  slug: string;
  position: number;
}

export interface PostSeriesInfo {
  series: { id: string; title: string; slug: string; description: string } | null;
  posts: SeriesNavPost[];
  current_position: number;
}

export async function getPostSeries(postId: string): Promise<PostSeriesInfo> {
  const res = await apiClient.get<PostSeriesInfo>(`/api/v1/posts/${postId}/series`);
  return res.data;
}

export async function updateSeriesPostPosition(seriesId: string, postId: string, position: number): Promise<void> {
  await apiClient.put(`/api/v1/series/${seriesId}/posts/${postId}/position`, { position });
}
