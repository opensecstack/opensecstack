import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Spinner } from "@/components/Spinner";
import { listMitigations } from "@/api/mitigations";
import { formatNumber, formatTs } from "@/lib/format";

export default function Mitigations(): JSX.Element {
  const { t } = useTranslation(["common", "mitigations"]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["mitigations"],
    queryFn: () => listMitigations(100),
    refetchInterval: 5_000,
  });

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;

  const mitigations = data?.mitigations ?? [];
  const count = data?.count ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{t("mitigations:title")}</h1>
        <span className="text-sm text-slate-500">
          {t("mitigations:count", { count })}
        </span>
      </div>
      {mitigations.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md text-sm shadow-sm overflow-hidden">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("mitigations:fields.started_at")}</th>
              <th className="px-3 py-2">{t("mitigations:fields.ended_at")}</th>
              <th className="px-3 py-2">{t("mitigations:fields.src_ip")}</th>
              <th className="px-3 py-2">{t("mitigations:fields.rule_id")}</th>
              <th className="px-3 py-2 text-right">
                {t("mitigations:fields.packets_dropped")}
              </th>
              <th className="px-3 py-2 text-right">
                {t("mitigations:fields.bytes_dropped")}
              </th>
              <th className="px-3 py-2">{t("mitigations:fields.emitted")}</th>
            </tr>
          </thead>
          <tbody>
            {mitigations.map((m) => (
              <tr key={m.id} className="border-t border-slate-100">
                <td className="px-3 py-2">{formatTs(m.started_at)}</td>
                <td className="px-3 py-2">{m.ended_at ? formatTs(m.ended_at) : "—"}</td>
                <td className="px-3 py-2 font-mono">{m.src_ip}</td>
                <td className="px-3 py-2 font-mono text-xs">{m.rule_id}</td>
                <td className="px-3 py-2 text-right">{formatNumber(m.packets_dropped)}</td>
                <td className="px-3 py-2 text-right">{formatNumber(m.bytes_dropped)}</td>
                <td className="px-3 py-2">
                  {m.emitted ? t("mitigations:emitted.yes") : t("mitigations:emitted.no")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
