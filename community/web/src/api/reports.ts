import { apiClient } from "./client";

export type ReportReason = "spam" | "harassment" | "off_topic" | "misinformation" | "other";

export interface Report {
  id: string;
  reason: ReportReason;
  note: string;
  status: "pending" | "resolved" | "dismissed";
  created_at: string;
  reporter_username: string;
  post_id: string | null;
  post_title: string | null;
  post_slug: string | null;
  comment_id: string | null;
  comment_body: string | null;
  post_author_username: string | null;
  comment_author_username: string | null;
}

export async function reportPost(postId: string, reason: ReportReason, note = ""): Promise<void> {
  await apiClient.post(`/api/v1/posts/${postId}/report`, { reason, note });
}

export async function reportComment(commentId: string, reason: ReportReason, note = ""): Promise<void> {
  await apiClient.post(`/api/v1/comments/${commentId}/report`, { reason, note });
}

export async function listReports(status = "pending", limit = 20, offset = 0): Promise<{ reports: Report[]; count: number }> {
  const r = await apiClient.get("/api/v1/mod/reports", { params: { status, limit, offset } });
  return r.data;
}

export async function resolveReport(id: string, action: "resolve" | "dismiss", note?: string): Promise<void> {
  await apiClient.post(`/api/v1/mod/reports/${id}/resolve`, { action, note });
}
