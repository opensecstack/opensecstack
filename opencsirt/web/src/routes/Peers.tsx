import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { listPeers, handshakePeer } from "@/api/peers";
import { formatTs } from "@/lib/format";

export default function Peers(): JSX.Element {
  const { t } = useTranslation(["common", "peers"]);
  const qc = useQueryClient();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["peers"],
    queryFn: listPeers,
  });

  const handshake = useMutation({
    mutationFn: (id: string) => handshakePeer(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["peers"] }),
  });

  if (isLoading) return <Spinner />;
  if (isError) return <p className="text-red-600">{t("common:labels.error")}</p>;
  const items = data?.peers ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">{t("peers:title")}</h1>
        <span className="text-sm text-slate-500">{data?.count ?? 0}</span>
      </div>
      {items.length === 0 ? (
        <p className="text-slate-500">{t("common:labels.empty")}</p>
      ) : (
        <table className="w-full bg-white rounded-md text-sm shadow-sm overflow-hidden">
          <thead className="bg-slate-100 text-left">
            <tr>
              <th className="px-3 py-2">{t("peers:fields.name")}</th>
              <th className="px-3 py-2">{t("peers:fields.country")}</th>
              <th className="px-3 py-2">{t("peers:fields.registry")}</th>
              <th className="px-3 py-2">{t("peers:fields.trust")}</th>
              <th className="px-3 py-2">{t("peers:fields.last_handshake")}</th>
              <th className="px-3 py-2">{t("peers:fields.fingerprint")}</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {items.map((p) => (
              <tr key={p.id} className="border-t border-slate-100 hover:bg-slate-50">
                <td className="px-3 py-2 font-medium">{p.name}</td>
                <td className="px-3 py-2">{p.country}</td>
                <td className="px-3 py-2 uppercase text-xs">{p.registry}</td>
                <td className="px-3 py-2">{t(`peers:trust.${p.trust}`)}</td>
                <td className="px-3 py-2">{formatTs(p.last_handshake_at)}</td>
                <td className="px-3 py-2 font-mono text-xs">{p.ed25519_fingerprint || "—"}</td>
                <td className="px-3 py-2">
                  <Button
                    variant="secondary"
                    disabled={handshake.isPending}
                    onClick={() => handshake.mutate(p.id)}
                  >
                    {t("common:actions.handshake")}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
