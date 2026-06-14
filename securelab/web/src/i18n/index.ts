import i18n from "i18next";
import { initReactI18next } from "react-i18next";

const en = {
  common: {
    app_name: "SecureLab",
    loading: "Loading...",
    error: "An error occurred",
    retry: "Retry",
    footer: "SecureLab v{{version}} — OpenSecStack",
    nav: {
      dashboard: "Dashboard",
      scenarios: "Scenarios",
      results: "Results",
      mitre_map: "MITRE Map",
      gap_analysis: "Gap Analysis",
      logout: "Logout",
    },
    actions: {
      login: "Login",
      run: "Run",
      cancel: "Cancel",
      view: "View",
    },
    labels: {
      username: "Username",
      password: "Password",
      environment: "Environment",
      severity: "Severity",
      tag: "Tag",
      status: "Status",
      detected: "Detected",
      detection_latency: "Detection Latency",
      started_at: "Started At",
      scenario: "Scenario",
      technique: "Technique",
      tactic: "Tactic",
      notes: "Notes",
    },
  },
};

void i18n.use(initReactI18next).init({
  resources: {
    en: {
      common: en.common,
    },
  },
  lng: "en",
  fallbackLng: "en",
  defaultNS: "common",
  ns: ["common"],
  interpolation: { escapeValue: false },
  returnNull: false,
});

export default i18n;
