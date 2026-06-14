import { create } from "zustand";
import i18n from "@/i18n";

type Locale = "sq" | "en";

interface LocaleState {
  locale: Locale;
  setLocale: (l: Locale) => void;
}

export const useLocale = create<LocaleState>((set) => ({
  locale: (i18n.language as Locale) || "sq",
  setLocale: (l) => {
    void i18n.changeLanguage(l);
    set({ locale: l });
  },
}));
