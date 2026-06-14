import { apiClient } from "./client";

export async function subscribePost(id: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${id}/subscribe`);
}

export async function unsubscribePost(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${id}/subscribe`);
}

export async function getPostSubscriptionStatus(id: string): Promise<boolean> {
  const res = await apiClient.get<{ subscribed: boolean }>(`/api/v1/posts/${id}/subscribe`);
  return res.data.subscribed;
}
