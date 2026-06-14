import { create } from "zustand";
import { isJwtExpired, jwtExpiryMs } from "@/lib/jwt";

const STORAGE_KEY = "opencsirt.token";

interface AuthState {
  token: string | null;
  setToken: (t: string | null) => void;
  isAuthenticated: () => boolean;
  logout: () => void;
}

function readStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  const raw = window.sessionStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  if (isJwtExpired(raw)) {
    window.sessionStorage.removeItem(STORAGE_KEY);
    return null;
  }
  return raw;
}

function writeToken(t: string | null): void {
  if (typeof window === "undefined") return;
  if (t) window.sessionStorage.setItem(STORAGE_KEY, t);
  else window.sessionStorage.removeItem(STORAGE_KEY);
}

let expiryTimer: ReturnType<typeof setTimeout> | null = null;

function scheduleExpiry(token: string | null, onExpire: () => void): void {
  if (expiryTimer) {
    clearTimeout(expiryTimer);
    expiryTimer = null;
  }
  if (!token) return;
  const expMs = jwtExpiryMs(token);
  if (expMs === null) return;
  const delay = Math.max(0, expMs - Date.now());
  expiryTimer = setTimeout(onExpire, delay);
}

export const useAuth = create<AuthState>((set, get) => {
  const initial = readStoredToken();
  const expire = (): void => {
    writeToken(null);
    set({ token: null });
  };
  scheduleExpiry(initial, expire);

  return {
    token: initial,
    setToken: (t) => {
      if (t && isJwtExpired(t)) {
        writeToken(null);
        set({ token: null });
        return;
      }
      writeToken(t);
      set({ token: t });
      scheduleExpiry(t, () => {
        writeToken(null);
        set({ token: null });
      });
    },
    isAuthenticated: () => {
      const t = get().token;
      if (!t) return false;
      if (isJwtExpired(t)) {
        writeToken(null);
        set({ token: null });
        return false;
      }
      return true;
    },
    logout: () => {
      if (expiryTimer) {
        clearTimeout(expiryTimer);
        expiryTimer = null;
      }
      writeToken(null);
      set({ token: null });
    },
  };
});
