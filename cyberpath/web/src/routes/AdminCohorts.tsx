import { useTranslation } from "react-i18next";

export default function AdminCohorts(): JSX.Element {
  const { t } = useTranslation(["common", "tracks"]);
  return (
    <section className="space-y-4">
      <h1 className="text-2xl font-bold">{t("common:nav.admin")}</h1>
      <p className="text-slate-600">{t("tracks:placeholder")}</p>
      <p className="text-xs text-slate-500">
        Cohort management UI lands in v1.0.0. This page is gated by RequireAuth(role=admin).
      </p>
    </section>
  );
}
