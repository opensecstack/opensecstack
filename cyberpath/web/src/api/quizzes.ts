import { apiClient } from "./client";

export interface QuizQuestion {
  id: string;
  text: string;
  type: "single" | "multi";
  options: { key: string; text: string }[];
}

export interface Quiz {
  id: string;
  title: string;
  questions: QuizQuestion[];
  passing_score: number; // 0-100
}

export interface QuizResult {
  passed: boolean;
  score: number;
  correct_count: number;
  total_count: number;
}

export async function getQuiz(id: string): Promise<Quiz> {
  const res = await apiClient.get<Quiz>(`/api/v1/quizzes/${encodeURIComponent(id)}`);
  return res.data;
}

export async function submitQuiz(
  id: string,
  answers: Record<string, string | string[]>,
): Promise<QuizResult> {
  const res = await apiClient.post<QuizResult>(
    `/api/v1/quizzes/${encodeURIComponent(id)}/submit`,
    { answers },
  );
  return res.data;
}
