import { apiClient } from "./client";
export async function login(username, password) {
    const res = await apiClient.post("/api/v1/auth/login", {
        username,
        password,
    });
    return res.data;
}
