import { apiClient } from "./client";
import type { PostListResponse } from "./posts";

export interface Tag {
  id: string;
  name: string;
  slug: string;
  description: string;
  color: string;
  post_count: number;
  follower_count: number;
}

export interface TrendingTag {
  id: string;
  name: string;
  slug: string;
  color: string;
  post_count: number;
}

export interface TagListResponse {
  tags: Tag[];
  count: number;
}

export async function fetchTrendingTags(): Promise<{ tags: TrendingTag[] }> {
  const res = await apiClient.get<{ tags: TrendingTag[] }>("/api/v1/tags/trending");
  return res.data;
}

export async function listTags(limit = 30): Promise<TagListResponse> {
  const res = await apiClient.get<TagListResponse>("/api/v1/tags", { params: { limit } });
  return res.data;
}

export async function getTag(slug: string): Promise<Tag> {
  const res = await apiClient.get<Tag>(`/api/v1/tags/${slug}`);
  return res.data;
}

export async function listPostsByTag(slug: string, sort = "latest", limit = 20, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>(`/api/v1/tags/${slug}/posts`, { params: { sort, limit, offset } });
  return res.data;
}

export async function followTag(slug: string): Promise<void> {
  await apiClient.post(`/api/v1/tags/${slug}/follow`);
}

export async function adminCreateTag(data: { name: string; description: string; color: string }): Promise<Tag> {
  const res = await apiClient.post<Tag>("/api/v1/admin/tags", data);
  return res.data;
}

export async function adminUpdateTag(slug: string, data: { name: string; description: string; color: string }): Promise<Tag> {
  const res = await apiClient.put<Tag>(`/api/v1/admin/tags/${slug}`, data);
  return res.data;
}

export async function adminDeleteTag(slug: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/tags/${slug}`);
}

export interface TagAlias {
  alias: string;
  tag_slug: string;
}

export interface TagAliasListResponse {
  aliases: TagAlias[];
}

export async function fetchTagAliases(slug: string): Promise<TagAliasListResponse> {
  const res = await apiClient.get<TagAliasListResponse>(`/api/v1/admin/tags/${slug}/aliases`);
  return res.data;
}

export async function createTagAlias(slug: string, alias: string): Promise<TagAlias> {
  const res = await apiClient.post<TagAlias>(`/api/v1/admin/tags/${slug}/aliases`, { alias });
  return res.data;
}

export async function deleteTagAlias(alias: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/tags/aliases/${alias}`);
}
