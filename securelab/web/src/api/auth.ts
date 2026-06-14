import { apiClient } from "./client";

export interface LoginResponse {
  token: string;
  expires_at: string;
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
