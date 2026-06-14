import { apiClient } from "./client";

export interface MutedUser {
  id: string;
  username: string;
  display_name: string;
  avatar_url: string | null;
}

export async function muteUser(username: string): Promise<void> {
  await apiClient.post(`/api/v1/users/${username}/mute`);
}

export async function unmuteUser(username: string): Promise<void> {
  await apiClient.delete(`/api/v1/users/${username}/mute`);
}

export async function getMuteStatus(username: string): Promise<{ muted: boolean }> {
  const r = await apiClient.get(`/api/v1/users/${username}/mute-status`);
  return r.data;
}

export async function listMutedUsers(): Promise<{ users: MutedUser[] }> {
  const r = await apiClient.get("/api/v1/me/mutes");
  return r.data;
}
