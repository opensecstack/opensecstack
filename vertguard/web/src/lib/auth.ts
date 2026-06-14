const KEY = "vertguard.jwt";

export function getToken(): string | null {
  return localStorage.getItem(KEY);
}

export function setToken(t: string) {
  localStorage.setItem(KEY, t);
}

export function clearToken() {
  localStorage.removeItem(KEY);
}

export interface JWTClaims {
  sub?: string;
  role?: string;
  exp?: number;
}

export function parseClaims(token: string): JWTClaims | null {
  try {
    const part = token.split(".")[1];
    return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return null;
  }
}
