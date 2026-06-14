import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { TlpBadge } from "@/components/TlpBadge";
import { listAdvisories, withdrawAdvisory } from "@/api/advisories";
import { formatTs } from "@/lib/format";

export default function Advisories(): JSX.Element {
  const { t } = useTranslation(["common", "advisories"]);
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["advisories"],
    queryFn: () => listAdvisories(50, 0),
  });

  const withdraw = useMutation({
    mutationFn: (id: string) => withdrawAdvisory(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["advisories"] }),
  });

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;
  const items = data?.advisories ?? [];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">{t("advisories:title")}</h1>
      {items.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md text-sm shadow-sm overflow-hidden">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("advisories:fields.csaf_id")}</th>
              <th className="px-3 py-2">{t("advisories:fields.title")}</th>
              <th className="px-3 py-2">{t("advisories:fields.tlp")}</th>
              <th className="px-3 py-2">{t("advisories:fields.state")}</th>
              <th className="px-3 py-2">{t("advisories:fields.version")}</th>
              <th className="px-3 py-2">{t("advisories:fields.published_at")}</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id} className="border-t border-slate-100 hover:bg-slate-50">
                <td className="px-3 py-2 font-mono text-xs">
                  <Link to={`/advisories/${a.id}`} className="underline">{a.csaf_id}</Link>
                </td>
                <td className="px-3 py-2">{a.title}</td>
                <td className="px-3 py-2"><TlpBadge tlp={a.tlp} /></td>
                <td className="px-3 py-2">{t(`advisories:states.${a.state}`)}</td>
                <td className="px-3 py-2">{a.version}</td>
                <td className="px-3 py-2">{formatTs(a.published_at)}</td>
                <td className="px-3 py-2">
                  {a.state === "published" && (
                    <Button
                      variant="danger"
                      disabled={withdraw.isPending}
                      onClick={() => withdraw.mutate(a.id)}
                    >
                      {t("common:actions.withdraw")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
