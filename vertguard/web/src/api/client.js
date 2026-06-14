import axios from "axios";
import { clearToken, getToken } from "../lib/auth";
// Empty default → same-origin requests, routed via Vite proxy in dev or
// reverse proxy in prod. Override with VITE_API_BASE_URL only if needed.
const baseURL = import.meta.env.VITE_API_BASE_URL ?? "";
export const apiClient = axios.create({
    baseURL,
    headers: { "Content-Type": "application/json" },
    timeout: 15000,
});
apiClient.interceptors.request.use((config) => {
    const token = getToken();
    if (token) {
        config.headers.set("Authorization", `Bearer ${token}`);
    }
    return config;
});
apiClient.interceptors.response.use((r) => r, (error) => {
    if (error?.response?.status === 401) {
        clearToken();
    }
    return Promise.reject(error);
});
