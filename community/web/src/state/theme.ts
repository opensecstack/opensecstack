import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ThemeState {
  dark: boolean;
  toggle: () => void;
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      dark: false,
      toggle: () => {
        const next = !get().dark;
        set({ dark: next });
        document.documentElement.classList.toggle("dark", next);
      },
    }),
    { name: "sin:theme" }
  )
);

// Apply on load
if (typeof window !== "undefined") {
  const stored = localStorage.getItem("sin:theme");
  if (stored) {
    try {
      const { state } = JSON.parse(stored);
      if (state?.dark) document.documentElement.classList.add("dark");
    } catch {
      // ignore malformed storage
    }
  }
}
