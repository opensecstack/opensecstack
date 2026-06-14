const KEY = "vertguard.jwt";
export function getToken() {
    return localStorage.getItem(KEY);
}
export function setToken(t) {
    localStorage.setItem(KEY, t);
}
export function clearToken() {
    localStorage.removeItem(KEY);
}
export function parseClaims(token) {
    try {
        const part = token.split(".")[1];
        return JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
    }
    catch {
        return null;
    }
}
