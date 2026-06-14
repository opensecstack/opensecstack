import { apiClient } from "./client";

export interface Comment {
  id: string;
  post_id: string;
  parent_id: string | null;
  author_id: string;
  author_username: string;
  author_display_name: string;
  author_avatar_url: string | null;
  body: string;
  created_at: string;
  updated_at: string;
  reaction_count: number;
  viewer_reacted: boolean;
}

export interface CommentListResponse {
  comments: Comment[];
  count: number;
  total: number;
  has_more: boolean;
}

export async function listComments(
  postId: string,
  sort?: string,
  page = 1,
  limit = 20,
): Promise<CommentListResponse> {
  const offset = (page - 1) * limit;
  const res = await apiClient.get<CommentListResponse>(`/api/v1/posts/${postId}/comments`, {
    params: { ...(sort ? { sort } : {}), limit, offset },
  });
  return res.data;
}

export async function createComment(postId: string, body: string, parentId?: string): Promise<{ id: string }> {
  const res = await apiClient.post<{ id: string }>(`/api/v1/posts/${postId}/comments`, {
    body,
    ...(parentId ? { parent_id: parentId } : {}),
  });
  return res.data;
}

export async function deleteComment(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/comments/${id}`);
}

export async function updateComment(id: string, body: string): Promise<void> {
  await apiClient.put(`/api/v1/comments/${id}`, { body });
}
