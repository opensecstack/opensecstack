import { useTranslation } from "react-i18next";

export default function Metrics() {
  const { t } = useTranslation();
  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">{t("metrics:title")}</h1>
      <div className="bg-slate-900 border border-slate-800 rounded p-4 max-w-xl">
        <p className="text-sm text-slate-300 mb-3">
          {t("metrics:intro")}
        </p>
        <a
          href="/metrics"
          target="_blank"
          rel="noreferrer"
          className="inline-block bg-indigo-500 hover:bg-indigo-400 rounded px-3 py-1.5 text-sm font-medium"
        >
          {t("metrics:open")}
        </a>
        <p className="text-xs text-slate-500 mt-3">
          {t("metrics:footnote")}
        </p>
      </div>
    </div>
  );
}
