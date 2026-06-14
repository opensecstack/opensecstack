import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { api } from "../lib/api";

export default function Dashboard() {
  const { t } = useTranslation();
  const { data, isLoading, error } = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 30_000,
  });

  if (isLoading) return <div className="text-slate-400">{t("common:labels.loading")}</div>;
  if (error)
    return (
      <div className="text-rose-400">
        {t("dashboard:errors.health_failed", { detail: String(error) })}
      </div>
    );
  if (!data) return null;

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-6">{t("dashboard:title")}</h1>
      <div className="grid grid-cols-2 gap-4 max-w-2xl">
        <Card label={t("dashboard:fields.status")} value={data.status} accent={data.status === "ok" ? "emerald" : "amber"} />
        <Card label={t("dashboard:fields.database")} value={data.db} />
        <Card label={t("dashboard:fields.version")} value={data.version} />
        <Card label={t("dashboard:fields.commit")} value={data.commit} />
      </div>
      <h2 className="text-lg font-semibold mt-8 mb-3">{t("dashboard:modules")}</h2>
      <div className="grid grid-cols-3 gap-3 max-w-3xl">
        {Object.entries(data.modules).map(([k, v]) => (
          <Card key={k} label={k} value={v} />
        ))}
      </div>
    </div>
  );
}

function Card({ label, value, accent }: { label: string; value: string; accent?: string }) {
  const color = accent === "emerald" ? "text-emerald-300" : accent === "amber" ? "text-amber-300" : "text-slate-100";
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3">
      <div className="text-xs uppercase text-slate-500">{label}</div>
      <div className={`mt-1 text-sm ${color}`}>{value}</div>
    </div>
  );
}
