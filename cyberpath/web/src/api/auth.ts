import { apiClient } from "./client";
import type { AuthUser, AuthTokens } from "@/state/auth";

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: "Bearer";
  expires_in: number;
  user: AuthUser;
}

export interface RefreshResponse extends AuthTokens {}

export const auth = {
  async login(email: string, password: string): Promise<LoginResponse> {
    const res = await apiClient.post<LoginResponse>("/api/v1/auth/login", {
      email,
      password,
    });
    return res.data;
  },
  async refresh(refresh_token: string): Promise<RefreshResponse> {
    const res = await apiClient.post<RefreshResponse>("/api/v1/auth/refresh", {
      refresh_token,
    });
    return res.data;
  },
  async logout(): Promise<void> {
    // Server-side logout endpoint not yet exposed in v1.0.0 contract;
    // client-side state clear happens in the auth store. Reserved for v0.2.0.
    return;
  },
  async me(): Promise<AuthUser> {
    const res = await apiClient.get<AuthUser>("/api/v1/auth/me");
    return res.data;
  },
};
