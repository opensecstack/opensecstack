import { api } from './client'

export interface LoginResponse {
  access_token: string
  token_type: string
  expires_in: number
  require_totp?: boolean
}

export const login = (username: string, password: string, totpCode?: string) =>
  api.post<LoginResponse>('/api/v1/auth/login', { username, password, totp_code: totpCode }).then(r => r.data)

export const register = (username: string, email: string, password: string) =>
  api.post('/api/v1/auth/register', { username, email, password }).then(r => r.data)

export const forgotPassword = (email: string) =>
  api.post('/api/v1/auth/forgot-password', { email }).then(r => r.data)

export const resetPassword = (token: string, password: string) =>
  api.post('/api/v1/auth/reset-password', { token, new_password: password }).then(r => r.data)
