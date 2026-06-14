import { apiClient } from "./client";

export async function blockUser(username: string): Promise<void> {
  await apiClient.post(`/api/v1/users/${username}/block`);
}

export async function unblockUser(username: string): Promise<void> {
  await apiClient.delete(`/api/v1/users/${username}/block`);
}

export async function getBlockStatus(username: string): Promise<{ blocking: boolean }> {
  const r = await apiClient.get(`/api/v1/users/${username}/block-status`);
  return r.data;
}
