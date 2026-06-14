import { apiClient } from "./client";
import { useAuthStore } from "@/state/auth";

export interface DeletionRequest {
  id: string;
  status: string;
  requested_at: string;
  scheduled_for: string;
}

export interface AdminDeletionRequest {
  id: string;
  status: string;
  requested_at: string;
  scheduled_for: string;
  username: string;
  email: string;
  display_name: string;
}

export async function requestDeletion(): Promise<{ scheduled_for: string; message: string }> {
  const r = await apiClient.post("/api/v1/me/deletion-request");
  return r.data;
}

export async function cancelDeletion(): Promise<void> {
  await apiClient.delete("/api/v1/me/deletion-request");
}

export async function getDeletionStatus(): Promise<{ request: DeletionRequest | null }> {
  const r = await apiClient.get("/api/v1/me/deletion-request");
  return r.data;
}

export async function adminListDeletionRequests(): Promise<{ requests: AdminDeletionRequest[] }> {
  const r = await apiClient.get("/api/v1/admin/deletion-requests");
  return r.data;
}

export async function adminProcessDeletion(id: string): Promise<void> {
  await apiClient.post(`/api/v1/admin/deletion-requests/${id}/process`);
}

export async function exportMyData(): Promise<Blob> {
  const token = useAuthStore.getState().token;
  const res = await fetch("/api/v1/me/export", {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Export failed: ${res.status}`);
  }
  return res.blob();
}
