import { apiClient } from "./client";

export interface TOTPSetupResponse {
  secret: string;
  qr_url: string;
}

export interface TOTPStatusResponse {
  enabled: boolean;
}

export async function setupTOTP(): Promise<TOTPSetupResponse> {
  const res = await apiClient.post<TOTPSetupResponse>("/api/v1/me/totp/setup");
  return res.data;
}

export async function confirmTOTP(secret: string, code: string): Promise<{ enabled: boolean }> {
  const res = await apiClient.post<{ enabled: boolean }>("/api/v1/me/totp/confirm", { secret, code });
  return res.data;
}

export async function disableTOTP(code: string): Promise<void> {
  await apiClient.delete("/api/v1/me/totp", { data: { code } });
}

export async function getTOTPStatus(): Promise<TOTPStatusResponse> {
  const res = await apiClient.get<TOTPStatusResponse>("/api/v1/me/totp");
  return res.data;
}
