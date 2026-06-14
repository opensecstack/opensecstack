import axios, { type AxiosInstance, type InternalAxiosRequestConfig } from "axios";
import { useAuthStore } from "@/store/authStore";

// Empty default — same-origin (Vite proxy in dev, reverse proxy in prod).
const baseURL = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? "";

export const apiClient: AxiosInstance = axios.create({
  baseURL,
  headers: { "Content-Type": "application/json" },
  timeout: 15000,
});

apiClient.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const auth = useAuthStore.getState();
  if (auth.isAuthenticated()) {
    config.headers.set("Authorization", `Bearer ${auth.token}`);
  }
  return config;
});

apiClient.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error?.response?.status === 401) {
      useAuthStore.getState().clearToken();
      window.location.href = "/login";
    }
    return Promise.reject(error);
  },
);
