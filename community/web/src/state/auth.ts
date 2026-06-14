import { create } from "zustand";
import { persist } from "zustand/middleware";

interface AuthState {
  token: string | null;
  role: string | null;
  username: string | null;
  emailVerified: boolean;
  login: (token: string, role: string, username: string, emailVerified?: boolean) => void;
  setEmailVerified: (verified: boolean) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      token: null,
      role: null,
      username: null,
      emailVerified: false,
      login: (token, role, username, emailVerified = false) =>
        set({ token, role, username, emailVerified }),
      setEmailVerified: (verified) => set({ emailVerified: verified }),
      logout: () => set({ token: null, role: null, username: null, emailVerified: false }),
    }),
    { name: "community-auth" },
  ),
);
