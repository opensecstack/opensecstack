import { apiClient } from "./client";

export interface ModNote {
  id: string;
  body: string;
  author_username: string;
  created_at: string;
}

export interface AdminUser {
  id: string;
  username: string;
  display_name: string;
  email: string | null;
  role: string;
  created_at: string;
  post_count: number;
  deactivated_at: string | null;
  platform_badge: string | null;
}

export interface Broadcast {
  id: string;
  body: string;
  link_url: string | null;
  created_at: string;
}

export async function listAdminUsers(limit = 50, offset = 0): Promise<{ users: AdminUser[]; count: number }> {
  const r = await apiClient.get("/api/v1/admin/users", { params: { limit, offset } });
  return r.data;
}

export async function setUserRole(username: string, role: string): Promise<void> {
  await apiClient.put(`/api/v1/admin/users/${username}/role`, { role });
}

export async function deactivateUser(username: string): Promise<void> {
  await apiClient.post(`/api/v1/admin/users/${username}/deactivate`);
}

export async function reactivateUser(username: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/users/${username}/deactivate`);
}

export async function getBroadcast(): Promise<{ broadcast: Broadcast | null }> {
  const r = await apiClient.get("/api/v1/broadcasts");
  return r.data;
}

export async function createBroadcast(body: string, link_url?: string, expires_at?: string): Promise<void> {
  await apiClient.post("/api/v1/admin/broadcasts", { body, link_url, expires_at });
}

export async function deleteBroadcast(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/broadcasts/${id}`);
}

export async function bulkSetRole(usernames: string[], role: string): Promise<{ updated: number }> {
  const r = await apiClient.post("/api/v1/admin/users/bulk-role", { usernames, role });
  return r.data;
}

export async function bulkBanUsers(usernames: string[], banned: boolean): Promise<{ updated: number }> {
  const r = await apiClient.post("/api/v1/admin/users/bulk-ban", { usernames, banned });
  return r.data;
}

export async function setUserBadge(username: string, badge: string): Promise<void> {
  await apiClient.put(`/api/v1/admin/users/${username}/badge`, { badge });
}

export async function removeUserBadge(username: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/users/${username}/badge`);
}

export async function listModNotes(username: string): Promise<ModNote[]> {
  const r = await apiClient.get(`/api/v1/admin/users/${username}/notes`);
  return r.data;
}

export async function createModNote(username: string, body: string): Promise<void> {
  await apiClient.post(`/api/v1/admin/users/${username}/notes`, { body });
}

export async function deleteModNote(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/admin/notes/${id}`);
}
