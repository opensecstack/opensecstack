import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import sq from "./locales/sq.json";
import en from "./locales/en.json";

const defaultLocale = (import.meta.env.VITE_DEFAULT_LOCALE as string) || "sq";

void i18n.use(initReactI18next).init({
  resources: {
    sq: {
      common: sq.common,
      scan: sq.scan,
      threatfeed: sq.threatfeed,
      dashboard: sq.dashboard,
      metrics: sq.metrics,
      not_found: sq.not_found,
    },
    en: {
      common: en.common,
      scan: en.scan,
      threatfeed: en.threatfeed,
      dashboard: en.dashboard,
      metrics: en.metrics,
      not_found: en.not_found,
    },
  },
  lng: defaultLocale,
  fallbackLng: "en",
  defaultNS: "common",
  ns: ["common", "scan", "threatfeed", "dashboard", "metrics", "not_found"],
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
