import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";

export default function NotFound(): JSX.Element {
  const { t } = useTranslation("not_found");
  return (
    <div className="text-center py-20">
      <h1 className="text-2xl font-semibold">{t("title")}</h1>
      <p className="text-slate-500 mt-2">{t("body")}</p>
      <Link to="/rules" className="text-slate-900 underline mt-4 inline-block">
        {t("back")}
      </Link>
    </div>
  );
}
