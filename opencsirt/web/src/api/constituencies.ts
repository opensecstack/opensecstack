import { apiClient } from "./client";

export type ConstituencyKind = "essential" | "important" | "out_of_scope";
export type Tlp = "clear" | "green" | "amber" | "red";

export interface Constituency {
  id: string;
  name: string;
  kind: ConstituencyKind;
  sector: string;
  country: string;
  tlp_default: Tlp;
  primary_contact: string;
  secondary_contact_email: string | null;
  created_at: string;
  updated_at: string;
}

export interface ConstituencyListResponse {
  constituencies: Constituency[];
  count: number;
}

export interface CreateConstituencyInput {
  name: string;
  kind: ConstituencyKind;
  sector: string;
  tlp_default?: Tlp;
  primary_contact?: string;
  secondary_contact_email?: string;
}

export async function listConstituencies(limit = 100, offset = 0): Promise<ConstituencyListResponse> {
  const res = await apiClient.get<ConstituencyListResponse>("/api/v1/constituencies", {
    params: { limit, offset },
  });
  return res.data;
}

export async function createConstituency(input: CreateConstituencyInput): Promise<Constituency> {
  const res = await apiClient.post<Constituency>("/api/v1/constituencies", input);
  return res.data;
}
