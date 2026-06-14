import { apiClient } from "./client";

export type ReactionKind = "heart" | "unicorn" | "fire" | "like" | "insight" | "celebrate";

export interface PostReactionsResponse {
  reactions: Record<string, number>;
  user_reactions: string[];
}

export async function fetchPostReactions(postId: string | number): Promise<PostReactionsResponse> {
  const res = await apiClient.get<PostReactionsResponse>(`/api/v1/posts/${postId}/reactions`);
  return res.data;
}

export async function addReaction(postId: string, kind: string): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/reactions`, { kind });
}

export async function removeReaction(postId: string, kind: string): Promise<void> {
  await apiClient.delete(`/api/v1/posts/${postId}/reactions/${kind}`);
}

export async function addCommentReaction(commentId: string): Promise<void> {
  await apiClient.post(`/api/v1/comments/${commentId}/reactions`, {});
}

export async function removeCommentReaction(commentId: string): Promise<void> {
  await apiClient.delete(`/api/v1/comments/${commentId}/reactions`);
}
