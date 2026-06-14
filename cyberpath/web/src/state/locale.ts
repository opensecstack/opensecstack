import { create } from "zustand";
import i18n from "@/i18n";

export type Locale = "sq" | "en";

interface LocaleState {
  locale: Locale;
  setLocale: (l: Locale) => void;
}

const STORAGE_KEY = "cyberpath.locale";

function initialLocale(): Locale {
  if (typeof window !== "undefined") {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored === "sq" || stored === "en") return stored;
  }
  const env = (import.meta.env.VITE_DEFAULT_LOCALE as string) || "sq";
  return env === "en" ? "en" : "sq";
}

export const useLocale = create<LocaleState>((set) => ({
  locale: initialLocale(),
  setLocale: (l) => {
    if (typeof window !== "undefined") {
      window.localStorage.setItem(STORAGE_KEY, l);
    }
    void i18n.changeLanguage(l);
    set({ locale: l });
  },
}));
