import { create } from "zustand";

export interface AuthUser {
  id: string;
  email: string;
  display_name: string;
  locale: "sq" | "en";
  role: "learner" | "instructor" | "admin" | "service";
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

interface AuthState {
  user: AuthUser | null;
  tokens: AuthTokens | null;
  login: (user: AuthUser, tokens: AuthTokens) => void;
  logout: () => void;
  refresh: (tokens: AuthTokens) => void;
}

const STORAGE_KEY = "cyberpath.auth";

interface PersistedAuth {
  user: AuthUser | null;
  tokens: AuthTokens | null;
}

function loadPersisted(): PersistedAuth {
  if (typeof window === "undefined") return { user: null, tokens: null };
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return { user: null, tokens: null };
    return JSON.parse(raw) as PersistedAuth;
  } catch {
    return { user: null, tokens: null };
  }
}

function persist(state: PersistedAuth): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Ignore quota / private-mode errors.
  }
}

export const useAuth = create<AuthState>((set) => {
  const initial = loadPersisted();
  return {
    user: initial.user,
    tokens: initial.tokens,
    login: (user, tokens) => {
      persist({ user, tokens });
      set({ user, tokens });
    },
    logout: () => {
      persist({ user: null, tokens: null });
      set({ user: null, tokens: null });
    },
    refresh: (tokens) => {
      set((s) => {
        persist({ user: s.user, tokens });
        return { tokens };
      });
    },
  };
});
