import { apiClient } from "./client";

export interface Environment {
  id: string;
  name: string;
  kind: string;
  target_url: string;
  status: string;
}

export async function listEnvironments(): Promise<Environment[]> {
  const res = await apiClient.get<Environment[]>("/api/v1/environments");
  return res.data;
}
