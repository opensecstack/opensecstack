import axios from "axios";
import { useAuthStore } from "@/state/auth";
import { isJwtExpired } from "@/lib/jwt";

export const apiClient = axios.create({ baseURL: "/" });

apiClient.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    if (isJwtExpired(token)) {
      useAuthStore.getState().logout();
    } else {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

apiClient.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) useAuthStore.getState().logout();
    if (err.response?.status === 429) {
      const retryAfterHeader = err.response.headers?.["retry-after"];
      const retryAfter = retryAfterHeader ? parseInt(retryAfterHeader, 10) : null;
      const seconds = retryAfter && !isNaN(retryAfter) ? retryAfter : null;
      const message = seconds
        ? `Too many requests. Please try again in ${seconds} seconds.`
        : "Too many requests. Please try again in a moment.";
      err.retryAfter = seconds;
      err.message429 = message;
    }
    return Promise.reject(err);
  },
);
