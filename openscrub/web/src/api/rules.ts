import { apiClient } from "./client";

export type RuleType = "blocklist" | "ratelimit" | "syncookie";

export interface Rule {
  id: string;
  type: RuleType;
  cidr?: string;
  pps?: number;
  port?: number;
  ttl_seconds: number;
  source: string;
  created_at: string;
  expires_at: string;
  created_by?: string | null;
}

export interface RuleListResponse {
  rules: Rule[];
  count: number;
}

export interface CreateRuleInput {
  type: RuleType;
  cidr?: string;
  pps?: number;
  port?: number;
  ttl_seconds: number;
  source?: string;
}

export interface ListRulesParams {
  limit?: number;
  // `offset` + `limit` pagination is part of the OpenAPI contract for
  // GET /api/v1/rules (see api/openapi.yaml).
  offset?: number;
  type?: RuleType;
}

export async function listRules(params: ListRulesParams = {}): Promise<RuleListResponse> {
  const res = await apiClient.get<RuleListResponse>("/api/v1/rules", {
    params,
  });
  return res.data;
}

export async function createRule(input: CreateRuleInput): Promise<Rule> {
  const res = await apiClient.post<Rule>("/api/v1/rules", input);
  return res.data;
}

export async function deleteRule(id: string): Promise<void> {
  await apiClient.delete(`/api/v1/rules/${id}`);
}
