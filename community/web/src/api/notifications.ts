import { apiClient } from "./client";

export interface Notification {
  id: string;
  type:
    | "comment_on_post"
    | "reaction_on_post"
    | "followed_by_user"
    | "mentioned_in_comment"
    | "welcome"
    | "password_changed"
    | "space_joined"
    | "space_member_joined"
    | "space_invite";
  post_id: string | null;
  comment_id: string | null;
  read: boolean;
  created_at: string;
  actor_username: string | null;
  actor_name: string | null;
  actor_avatar: string | null;
  post_title: string | null;
  post_slug: string | null;
  space_id: string | null;
  space_slug: string | null;
  space_name: string | null;
}

export interface NotificationListResponse {
  notifications: Notification[];
  count: number;
  unread_count: number;
  next_cursor: string | null;
}

export async function listNotifications(limit = 20, cursor?: string): Promise<NotificationListResponse> {
  const res = await apiClient.get<NotificationListResponse>("/api/v1/notifications", {
    params: { limit, ...(cursor ? { cursor } : {}) },
  });
  return res.data;
}

export async function markRead(id: string): Promise<void> {
  await apiClient.post(`/api/v1/notifications/${id}/read`);
}

export async function markAllRead(): Promise<void> {
  await apiClient.post("/api/v1/notifications/read-all");
}
