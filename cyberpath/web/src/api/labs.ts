import { apiClient } from "./client";

export interface LabSession {
  session_id: string;
  runtime: "docker" | "wasmtime";
  ws_url: string;
  image: string;
  started_at: string;
  expires_at: string;
}

export interface LabStop {
  session_id: string;
  ended_at: string;
  exit_status: string;
}

export interface LabStatus {
  session_id: string;
  state: "starting" | "running" | "stopped" | "expired";
  runtime: "docker" | "wasmtime";
  started_at: string;
  expires_at: string;
  resource_metrics: {
    cpu_seconds: number;
    memory_bytes: number;
  };
}

export async function startLab(id: string): Promise<LabSession> {
  const res = await apiClient.post<LabSession>(`/api/v1/labs/${encodeURIComponent(id)}/start`);
  return res.data;
}

export async function stopLab(id: string): Promise<LabStop> {
  const res = await apiClient.post<LabStop>(`/api/v1/labs/${encodeURIComponent(id)}/stop`);
  return res.data;
}

export async function labStatus(id: string): Promise<LabStatus> {
  const res = await apiClient.get<LabStatus>(`/api/v1/labs/${encodeURIComponent(id)}/status`);
  return res.data;
}
