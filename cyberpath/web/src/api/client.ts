import axios, { AxiosError, type AxiosInstance, type InternalAxiosRequestConfig } from "axios";

const baseURL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "http://localhost:8086";

const STORAGE_KEY = "cyberpath.auth";

interface PersistedTokens {
  tokens: {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  } | null;
}

function readTokens(): PersistedTokens["tokens"] {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return (JSON.parse(raw) as PersistedTokens).tokens;
  } catch {
    return null;
  }
}

function writeTokens(tokens: PersistedTokens["tokens"]): void {
  if (typeof window === "undefined") return;
  const raw = window.localStorage.getItem(STORAGE_KEY);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- merging into opaque persisted blob
  let parsed: any = {};
  if (raw) {
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = {};
    }
  }
  parsed.tokens = tokens;
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
}

export const apiClient: AxiosInstance = axios.create({
  baseURL,
  headers: { "Content-Type": "application/json" },
  timeout: 15000,
});

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const tokens = readTokens();
  if (tokens?.access_token) {
    config.headers.set("Authorization", `Bearer ${tokens.access_token}`);
  }
  return config;
});

let refreshInFlight: Promise<string | null> | null = null;

async function refreshTokens(): Promise<string | null> {
  const tokens = readTokens();
  if (!tokens?.refresh_token) return null;
  try {
    const res = await axios.post(`${baseURL}/api/v1/auth/refresh`, {
      refresh_token: tokens.refresh_token,
    });
    const next = res.data as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };
    writeTokens(next);
    return next.access_token;
  } catch {
    writeTokens(null);
    return null;
  }
}

apiClient.interceptors.response.use(
  (r) => r,
  async (error: AxiosError) => {
    const original = error.config as
      | (InternalAxiosRequestConfig & { _retry?: boolean })
      | undefined;
    if (error.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      refreshInFlight ??= refreshTokens().finally(() => {
        refreshInFlight = null;
      });
      const next = await refreshInFlight;
      if (next) {
        original.headers?.set("Authorization", `Bearer ${next}`);
        return apiClient.request(original);
      }
    }
    return Promise.reject(error);
  },
);
