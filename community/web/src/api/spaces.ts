import { apiClient } from "./client";

export interface Space {
  id: string;
  name: string;
  slug: string;
  description: string;
  icon_emoji: string;
  is_private: boolean;
  created_by: string;
  created_at: string;
  member_count: number;
  is_member: boolean;
  viewer_role: string | null;
}

export interface Channel {
  id: string;
  space_id: string;
  name: string;
  slug: string;
  description: string;
  type: "text" | "announcement";
  position: number;
}

export interface SpaceDetail {
  space: Space;
  channels: Channel[];
}

export async function listSpaces(limit = 24, offset = 0): Promise<{ spaces: Space[]; count: number }> {
  const res = await apiClient.get("/api/v1/spaces", { params: { limit, offset } });
  return res.data;
}

export async function getSpace(slug: string): Promise<SpaceDetail> {
  const res = await apiClient.get(`/api/v1/spaces/${slug}`);
  return res.data;
}

export async function createSpace(data: {
  name: string;
  description: string;
  icon_emoji: string;
  is_private: boolean;
}): Promise<Space> {
  const res = await apiClient.post("/api/v1/spaces", data);
  return res.data;
}

export async function updateSpace(slug: string, data: {
  name: string;
  description: string;
  icon_emoji: string;
  is_private: boolean;
}): Promise<void> {
  await apiClient.put(`/api/v1/spaces/${slug}`, data);
}

export async function deleteSpace(slug: string): Promise<void> {
  await apiClient.delete(`/api/v1/spaces/${slug}`);
}

export async function joinSpace(slug: string): Promise<void> {
  await apiClient.post(`/api/v1/spaces/${slug}/join`);
}

export async function leaveSpace(slug: string): Promise<void> {
  await apiClient.delete(`/api/v1/spaces/${slug}/leave`);
}

export async function createChannel(spaceSlug: string, data: {
  name: string;
  description: string;
  type: "text" | "announcement";
}): Promise<Channel> {
  const res = await apiClient.post(`/api/v1/spaces/${spaceSlug}/channels`, data);
  return res.data;
}

export async function getChannelPosts(spaceSlug: string, channelSlug: string, limit = 20, offset = 0) {
  const res = await apiClient.get(`/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/posts`, {
    params: { limit, offset },
  });
  return res.data;
}

export async function createChannelPost(spaceSlug: string, channelSlug: string, data: {
  title: string;
  body: string;
  tags: string[];
}) {
  const res = await apiClient.post(`/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/posts`, data);
  return res.data;
}

export async function deleteChannel(spaceSlug: string, channelSlug: string): Promise<void> {
  await apiClient.delete(`/api/v1/spaces/${spaceSlug}/channels/${channelSlug}`);
}

export async function createSpaceInvite(spaceSlug: string): Promise<{ code: string; expires_at: string }> {
  const res = await apiClient.post(`/api/v1/spaces/${spaceSlug}/invites`);
  return res.data;
}

export async function joinByInvite(code: string): Promise<{ space_slug: string }> {
  const res = await apiClient.post(`/api/v1/space-invites/${code}/join`);
  return res.data;
}

export async function getSpaceUnreadCounts(spaceSlug: string): Promise<Record<string, number>> {
  const res = await apiClient.get<Record<string, number>>(`/api/v1/spaces/${spaceSlug}/unread`);
  return res.data;
}

export async function markChannelRead(spaceSlug: string, channelSlug: string): Promise<void> {
  await apiClient.post(`/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/read`);
}
