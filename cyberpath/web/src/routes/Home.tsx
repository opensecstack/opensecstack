import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

export default function Home(): JSX.Element {
  const { t } = useTranslation("common");
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold text-slate-900">{t("appTitle")}</h1>
      <p className="text-slate-600">{t("tagline")}</p>
      <Link
        to="/tracks"
        className="inline-block rounded-md bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
      >
        {t("nav.tracks")}
      </Link>
    </section>
  );
}
