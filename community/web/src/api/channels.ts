import { apiClient } from "./client";

export interface MessageAttachment {
  id: string;
  file_url: string;
  file_name: string;
  mime_type: string;
  file_size: number;
}

export interface ChannelMessage {
  id: string;
  channel_id: string;
  author_id: string;
  author_username: string;
  author_display_name: string;
  author_avatar_url: string | null;
  content: string;
  edited_at: string | null;
  parent_id: string | null;
  created_at: string;
  reactions: Record<string, number>; // emoji -> count
  viewer_reacted: string[];           // emojis the viewer reacted with
  attachments: MessageAttachment[];
}

export interface MessagesResponse {
  messages: ChannelMessage[];
  has_more: boolean;
}

/** List messages for a channel — cursor-paginated; `before` is a message ID. */
export async function listChannelMessages(
  spaceSlug: string,
  channelSlug: string,
  params?: { before?: string; limit?: number },
): Promise<MessagesResponse> {
  const res = await apiClient.get(
    `/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/messages`,
    { params },
  );
  return res.data;
}

/** Send a new message to a channel. */
export async function sendChannelMessage(
  spaceSlug: string,
  channelSlug: string,
  data: { content: string; parent_id?: string },
): Promise<ChannelMessage> {
  const res = await apiClient.post(
    `/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/messages`,
    data,
  );
  return res.data;
}

/** Edit an existing message. */
export async function editChannelMessage(
  spaceSlug: string,
  channelSlug: string,
  messageId: string,
  content: string,
): Promise<ChannelMessage> {
  const res = await apiClient.put(
    `/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/messages/${messageId}`,
    { content },
  );
  return res.data;
}

/** Delete a message. */
export async function deleteChannelMessage(
  spaceSlug: string,
  channelSlug: string,
  messageId: string,
): Promise<void> {
  await apiClient.delete(
    `/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/messages/${messageId}`,
  );
}

/** Toggle an emoji reaction on a message. */
export async function toggleMessageReaction(
  spaceSlug: string,
  channelSlug: string,
  messageId: string,
  emoji: string,
): Promise<void> {
  await apiClient.post(
    `/api/v1/spaces/${spaceSlug}/channels/${channelSlug}/messages/${messageId}/reactions`,
    { emoji },
  );
}
