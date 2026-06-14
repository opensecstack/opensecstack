import { apiClient } from "./client";
import type { Post, PostListResponse } from "./posts";

export interface User {
  id: string;
  username: string;
  display_name: string;
  bio: string;
  avatar_url: string | null;
  platform_badge: string | null;
  role: string;
  created_at: string;
  website: string;
  github_username: string;
  twitter_username: string;
  location: string;
  certifications: string;
  specialization: string;
}

export async function getUser(username: string): Promise<User> {
  const res = await apiClient.get<User>(`/api/v1/users/${username}`);
  return res.data;
}

export async function getUserPosts(username: string, limit = 20, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>(`/api/v1/users/${username}/posts`, { params: { limit, offset } });
  return res.data;
}

export interface UpdateMeInput {
  display_name?: string;
  bio?: string;
  avatar_url?: string;
  platform_badge?: string;
}

export async function updateMe(input: UpdateMeInput): Promise<void> {
  await apiClient.put("/api/v1/users/me", input);
}

export async function updateProfile(data: {
  display_name?: string;
  bio?: string;
  avatar_url?: string | null;
  website?: string;
  github_username?: string;
  twitter_username?: string;
  location?: string;
  certifications?: string;
  specialization?: string;
}): Promise<void> {
  await apiClient.put("/api/v1/users/me", data);
}

export interface UserHit {
  username: string;
  display_name: string;
  avatar_url: string | null;
}

export async function getMyPosts(limit = 50, offset = 0): Promise<PostListResponse> {
  const res = await apiClient.get<PostListResponse>("/api/v1/me/posts", { params: { limit, offset } });
  return res.data;
}

export interface UserSearchResult {
  id: string;
  username: string;
  display_name: string;
  avatar_url?: string | null;
  bio?: string;
}

export async function searchUsers(q: string, limit = 20, offset = 0): Promise<{ users: UserSearchResult[]; count: number }> {
  const res = await apiClient.get<{ users: UserSearchResult[]; count: number }>("/api/v1/users/search", { params: { q, limit, offset } });
  return res.data;
}

export interface UserStats {
  post_count: number;
  reaction_count: number;
  view_count: number;
}

export async function getUserStats(username: string): Promise<UserStats> {
  const res = await apiClient.get<UserStats>(`/api/v1/users/${username}/stats`);
  return res.data;
}

export interface DirectoryUser {
  id: string;
  username: string;
  display_name: string;
  avatar_url: string | null;
  bio: string;
  post_count: number;
}

export interface UserDirectoryResponse {
  users: DirectoryUser[];
  total: number;
}

export async function fetchUsers(q = '', page = 1): Promise<UserDirectoryResponse> {
  const res = await apiClient.get<UserDirectoryResponse>(
    `/api/v1/users?q=${encodeURIComponent(q)}&page=${page}&limit=20`,
  );
  return res.data;
}

export async function getUserPinnedPost(username: string): Promise<{ post: Post | null }> {
  const res = await apiClient.get<{ post: Post | null }>(`/api/v1/users/${username}/pinned-post`);
  return res.data;
}

export interface SuggestedUser {
  username: string;
  display_name: string;
  avatar_url: string | null;
  bio: string;
  follower_count: number;
}

export async function fetchSuggestedUsers(): Promise<{ users: SuggestedUser[] }> {
  const res = await apiClient.get<{ users: SuggestedUser[] }>("/api/v1/users/suggested");
  return res.data;
}
