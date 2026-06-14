import { apiClient } from "./client";

export interface Scenario {
  id: string;
  name: string;
  description: string;
  mitre_technique_ids: string[];
  tags: string[];
  severity: "low" | "medium" | "high" | "critical";
  timeout_seconds: number;
  created_at: string;
}

export interface ScenarioRun {
  id: string;
  scenario_id: string;
  environment_id: string;
  status: "pending" | "running" | "passed" | "failed" | "error";
  started_at: string | null;
  finished_at: string | null;
  detected: boolean | null;
  detection_latency_ms: number | null;
  notes: string | null;
  attack_events?: AttackEvent[];
}

export interface AttackEvent {
  technique_id: string;
  technique_name: string;
  timestamp: string;
  success: boolean;
}

export interface RunScenarioResponse {
  run_id: string;
}

export async function listScenarios(): Promise<Scenario[]> {
  const res = await apiClient.get<Scenario[]>("/api/v1/scenarios");
  return res.data;
}

export async function getScenario(id: string): Promise<Scenario> {
  const res = await apiClient.get<Scenario>(`/api/v1/scenarios/${id}`);
  return res.data;
}

export async function runScenario(id: string, environmentId: string): Promise<RunScenarioResponse> {
  const res = await apiClient.post<RunScenarioResponse>(`/api/v1/scenarios/${id}/run`, {
    environment_id: environmentId,
  });
  return res.data;
}
