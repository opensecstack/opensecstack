import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";

export default function NotFound(): JSX.Element {
  const { t } = useTranslation("common");
  return (
    <section className="space-y-3 text-center">
      <h1 className="text-3xl font-bold">404</h1>
      <p className="text-slate-600">{t("errors.notFound")}</p>
      <Link to="/" className="text-brand underline">
        {t("nav.home")}
      </Link>
    </section>
  );
}
