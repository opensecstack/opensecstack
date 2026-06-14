import { apiClient } from "./client";
import type { ScenarioRun } from "./scenarios";

export interface RunsListResponse {
  runs: ScenarioRun[];
  total: number;
}

export async function listRuns(limit = 20, offset = 0): Promise<RunsListResponse> {
  const res = await apiClient.get<RunsListResponse>("/api/v1/runs", {
    params: { limit, offset },
  });
  return res.data;
}

export async function getRun(id: string): Promise<ScenarioRun> {
  const res = await apiClient.get<ScenarioRun>(`/api/v1/runs/${id}`);
  return res.data;
}
