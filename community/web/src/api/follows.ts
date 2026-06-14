import { apiClient } from "./client";

export interface FollowUser {
  username: string;
  display_name: string;
  avatar_url: string | null;
  platform_badge: string | null;
}

export async function followUser(username: string): Promise<void> {
  await apiClient.post(`/api/v1/users/${username}/follow`);
}

export async function unfollowUser(username: string): Promise<void> {
  await apiClient.delete(`/api/v1/users/${username}/follow`);
}

export async function getFollowStatus(username: string): Promise<{ following: boolean }> {
  const res = await apiClient.get<{ following: boolean }>(`/api/v1/users/${username}/follow`);
  return res.data;
}

export async function listFollowers(
  username: string,
  limit?: number,
  offset?: number,
): Promise<{ users: FollowUser[]; count: number }> {
  const res = await apiClient.get<{ users: FollowUser[]; count: number }>(
    `/api/v1/users/${username}/followers`,
    { params: { limit, offset } },
  );
  return res.data;
}

export async function listFollowing(
  username: string,
  limit?: number,
  offset?: number,
): Promise<{ users: FollowUser[]; count: number }> {
  const res = await apiClient.get<{ users: FollowUser[]; count: number }>(
    `/api/v1/users/${username}/following`,
    { params: { limit, offset } },
  );
  return res.data;
}

export interface FollowCounts {
  followers: number;
  following: number;
}

export async function getFollowCounts(username: string): Promise<FollowCounts> {
  const res = await apiClient.get<FollowCounts>(`/api/v1/users/${username}/follow-counts`);
  return res.data;
}
