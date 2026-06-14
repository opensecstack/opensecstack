import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import sq from "./locales/sq.json";
import en from "./locales/en.json";

const defaultLocale = (import.meta.env.VITE_DEFAULT_LOCALE as string) || "sq";

void i18n.use(initReactI18next).init({
  resources: {
    sq: { common: sq.common, tracks: sq.tracks },
    en: { common: en.common, tracks: en.tracks },
  },
  lng: defaultLocale,
  fallbackLng: "sq",
  defaultNS: "common",
  ns: ["common", "tracks"],
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
