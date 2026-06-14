import { apiClient } from "./client";

export interface Lesson {
  id: string;
  module_id: string;
  title_sq: string;
  title_en: string;
  body_sq: string;
  body_en: string;
  content_version_id: string;
  content_hash: string;
  quiz_id: string | null;
  lab_id: string | null;
}

export interface LessonCompletion {
  completion_id: string;
  lesson_id: string;
  content_version_id: string;
  score: number;
  completed_at: string;
  evidence_hash: string;
  citadel_emitted: "queued" | "emitted" | "failed" | "standalone";
}

export async function getLesson(id: string): Promise<Lesson> {
  const res = await apiClient.get<Lesson>(`/api/v1/lessons/${encodeURIComponent(id)}`);
  return res.data;
}

export async function completeLesson(
  id: string,
  body: { time_spent_seconds: number },
): Promise<LessonCompletion> {
  const res = await apiClient.post<LessonCompletion>(
    `/api/v1/lessons/${encodeURIComponent(id)}/complete`,
    body,
  );
  return res.data;
}
