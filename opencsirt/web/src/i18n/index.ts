import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import sq from "./locales/sq.json";
import en from "./locales/en.json";

const defaultLocale = (import.meta.env.VITE_DEFAULT_LOCALE as string) || "sq";

void i18n.use(initReactI18next).init({
  resources: {
    sq: {
      common: sq.common,
      constituencies: sq.constituencies,
      incidents: sq.incidents,
      advisories: sq.advisories,
      peers: sq.peers,
      metrics: sq.metrics,
      not_found: sq.not_found,
    },
    en: {
      common: en.common,
      constituencies: en.constituencies,
      incidents: en.incidents,
      advisories: en.advisories,
      peers: en.peers,
      metrics: en.metrics,
      not_found: en.not_found,
    },
  },
  lng: defaultLocale,
  fallbackLng: "en",
  defaultNS: "common",
  ns: ["common", "constituencies", "incidents", "advisories", "peers", "metrics", "not_found"],
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
