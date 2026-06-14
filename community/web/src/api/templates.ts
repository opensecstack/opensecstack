import { apiClient } from "./client";

export interface PostTemplate {
  id: number;
  name: string;
  title: string;
  body: string;
  tags: string[];
  created_at: string;
}

export async function listTemplates(): Promise<PostTemplate[]> {
  const res = await apiClient.get<PostTemplate[]>("/api/v1/me/templates");
  return res.data;
}

export async function createTemplate(data: {
  name: string;
  title: string;
  body: string;
  tags: string[];
}): Promise<PostTemplate> {
  const res = await apiClient.post<PostTemplate>("/api/v1/me/templates", data);
  return res.data;
}

export async function deleteTemplate(id: number): Promise<void> {
  await apiClient.delete(`/api/v1/me/templates/${id}`);
}
