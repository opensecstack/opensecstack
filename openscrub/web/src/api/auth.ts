import { apiClient } from "./client";

export interface LoginResponse {
  access_token: string;
  token_type: "Bearer";
  expires_at: string; // RFC-3339 timestamp
  role: string;
  sub: string;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await apiClient.post<LoginResponse>("/api/v1/auth/login", {
    username,
    password,
  });
  return res.data;
}
