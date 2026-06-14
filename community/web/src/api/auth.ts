import { apiClient } from "./client";

export interface LoginResponse {
  token: string;
  role: string;
  sub: string;
  expires_at: string;
  email_verified: boolean;
}

export interface AuthMethods {
  sinauth: boolean;
  sinauth_primary: boolean;
  native: boolean;
  github: boolean;
  google: boolean;
}

export async function getAuthMethods(): Promise<AuthMethods> {
  const res = await apiClient.get<AuthMethods>("/api/v1/auth/methods");
  return res.data;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await apiClient.post<LoginResponse>("/api/v1/auth/login", { username, password });
  return res.data;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  invite_code?: string;
}

export interface AuthResponse {
  token: string;
  role: string;
  sub: string;
  expires_at: string;
  email_verified: boolean;
}

export async function register(req: RegisterRequest): Promise<AuthResponse> {
  const r = await apiClient.post("/api/v1/auth/register", req);
  return r.data;
}

export async function validateInvite(code: string): Promise<{ valid: boolean; reason?: string }> {
  const r = await apiClient.get(`/api/v1/invites/${code}/validate`);
  return r.data;
}

export interface Invite {
  id: string;
  code: string;
  created_by_username: string;
  used_by_username: string | null;
  used_at: string | null;
  expires_at: string;
  created_at: string;
}

export async function generateInvite(): Promise<Invite> {
  const r = await apiClient.post("/api/v1/admin/invites");
  return r.data;
}

export async function listInvites(): Promise<Invite[]> {
  const r = await apiClient.get("/api/v1/admin/invites");
  return r.data.invites;
}

export async function forgotPassword(email: string): Promise<void> {
  await apiClient.post("/api/v1/auth/forgot-password", { email });
}

export async function resetPassword(token: string, password: string): Promise<void> {
  await apiClient.post("/api/v1/auth/reset-password", { token, password });
}

export async function verifyEmail(token: string): Promise<void> {
  await apiClient.get(`/api/v1/auth/verify-email?token=${encodeURIComponent(token)}`);
}

// Requires a valid Bearer token in the Authorization header (set by apiClient interceptor).
export async function resendVerification(): Promise<void> {
  await apiClient.post("/api/v1/auth/resend-verification");
}

// Requires a valid Bearer token in the Authorization header (set by apiClient interceptor).
export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await apiClient.put("/api/v1/me/password", {
    current_password: currentPassword,
    new_password: newPassword,
  });
}
