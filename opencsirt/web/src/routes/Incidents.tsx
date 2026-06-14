import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Spinner } from "@/components/Spinner";
import { listIncidents } from "@/api/incidents";
import { formatTs } from "@/lib/format";

export default function Incidents(): JSX.Element {
  const { t } = useTranslation(["common", "incidents"]);
  const { data, isLoading, isError } = useQuery({
    queryKey: ["incidents"],
    queryFn: () => listIncidents(50, 0),
    refetchInterval: 30_000,
  });

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;
  const items = data?.incidents ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{t("incidents:title")}</h1>
        <span className="text-sm text-slate-500">{data?.count ?? 0}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md text-sm shadow-sm overflow-hidden">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("incidents:fields.id")}</th>
              <th className="px-3 py-2">{t("incidents:fields.title")}</th>
              <th className="px-3 py-2">{t("incidents:fields.severity")}</th>
              <th className="px-3 py-2">{t("incidents:fields.constituency")}</th>
              <th className="px-3 py-2">{t("incidents:fields.status")}</th>
              <th className="px-3 py-2">{t("incidents:fields.created_at")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((i) => (
              <tr key={i.id} className="border-t border-slate-100 hover:bg-slate-50">
                <td className="px-3 py-2 font-mono text-xs">
                  <Link to={`/incidents/${i.id}`} className="underline">{i.id.slice(0, 8)}</Link>
                </td>
                <td className="px-3 py-2">{i.title}</td>
                <td className="px-3 py-2">{t(`incidents:severities.${i.severity}`)}</td>
                <td className="px-3 py-2 font-mono text-xs">{i.constituency_id?.slice(0, 8) ?? "—"}</td>
                <td className="px-3 py-2">{t(`incidents:statuses.${i.status}`)}</td>
                <td className="px-3 py-2">{formatTs(i.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
