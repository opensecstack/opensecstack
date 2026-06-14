import { apiClient } from "./client";

export type PostState = "draft" | "published" | "scheduled" | "archived";

export interface Post {
  id: string;
  author_id: string;
  author_username: string;
  author_display_name: string;
  author_avatar_url: string | null;
  author_platform_badge: string | null;
  title: string;
  slug: string;
  body?: string;
  cover_image_url: string | null;
  state: PostState;
  published_at: string | null;
  created_at: string;
  updated_at: string;
  tags: string[];
  reaction_count: number;
  comment_count: number;
  scheduled_at?: string | null;
  edited_at?: string | null;
  views?: number;
  locked?: boolean;
  pinned?: boolean;
  canonical_url?: string | null;
  reading_time_minutes?: number;
  sensitive?: boolean;
}

export interface PostListResponse {
  posts: Post[];
  count: number;
}

export async function listPosts(limit = 20, offset = 0, sort = "latest"): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>("/api/v1/posts", { params: { limit, offset, sort } });
  return res.data;
}

export async function listFeed(sort = "latest", limit = 20, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>("/api/v1/feed", { params: { sort, limit, offset } });
  return res.data;
}

export async function getFollowingFeed(limit = 20, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>(`/api/v1/feed/following?limit=${limit}&offset=${offset}`);
  return res.data;
}

export async function getTrendingFeed(limit = 20, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>(`/api/v1/feed/trending?limit=${limit}&offset=${offset}`);
  return res.data;
}

export async function getPost(slug: string): Promise<Post> {
  const res = await apiClient.get<Post>(`/api/v1/posts/${slug}`);
  return res.data;
}

export interface CreatePostInput {
  title: string;
  body?: string;
  cover_image_url?: string;
  tags?: string[];
  canonical_url?: string;
  sensitive?: boolean;
}

export async function createPost(input: CreatePostInput): Promise<{ id: string; slug: string }> {
  const res = await apiClient.post<{ id: string; slug: string }>("/api/v1/posts", input);
  return res.data;
}

export interface UpdatePostInput {
  title: string;
  body?: string;
  cover_image_url?: string;
  tags?: string[];
  canonical_url?: string;
  sensitive?: boolean;
}

export async function updatePost(id: string, input: UpdatePostInput): Promise<void> {
  await apiClient.put(`/api/v1/posts/${id}`, input);
}

export async function publishPost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/publish`);
}

export async function deletePost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}`);
}

export async function lockPost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/lock`);
}

export async function unlockPost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}/lock`);
}

export async function schedulePost(id: string, scheduledAt: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/schedule`, { scheduled_at: scheduledAt });
}

export async function unschedulePost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}/schedule`);
}

export interface RelatedPost {
  id: string;
  title: string;
  slug: string;
  cover_image_url: string | null;
  created_at: string;
  author: {
    username: string;
    display_name: string;
    avatar_url: string | null;
  };
}

export interface RelatedPostsResponse {
  posts: RelatedPost[];
}

export async function fetchRelatedPosts(postId: string): Promise<RelatedPostsResponse> {
  const res = await apiClient.get<RelatedPostsResponse>(`/api/v1/posts/${postId}/related`);
  return res.data;
}

export interface ScheduledPost {
  id: string;
  title: string;
  slug: string;
  cover_image_url: string | null;
  scheduled_at: string;
  created_at: string;
  updated_at: string;
}

export interface ScheduledPostsResponse {
  posts: ScheduledPost[];
  total: number;
}

export async function getScheduledPosts(): Promise<ScheduledPostsResponse> {
  const res = await apiClient.get<ScheduledPostsResponse>("/api/v1/me/scheduled");
  return res.data;
}
