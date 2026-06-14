import { useState } from "react";
import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { getAdvisoryCsaf, publishAdvisory, withdrawAdvisory } from "@/api/advisories";

export default function AdvisoryDetail(): JSX.Element {
  const { t } = useTranslation(["common", "advisories"]);
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const csaf = useQuery({
    queryKey: ["advisory-csaf", id],
    queryFn: () => getAdvisoryCsaf(id),
    enabled: !!id,
  });

  const [confirmPublish, setConfirmPublish] = useState(false);
  const [confirmWithdraw, setConfirmWithdraw] = useState(false);

  const publish = useMutation({
    mutationFn: () => publishAdvisory(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["advisories"] });
      setConfirmPublish(false);
    },
  });

  const withdraw = useMutation({
    mutationFn: () => withdrawAdvisory(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["advisories"] });
      setConfirmWithdraw(false);
    },
  });

  if (csaf.isLoading) return <Spinner />;
  if (csaf.isError) return <p className="text-red-600">{t("common:labels.error")}</p>;

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h1 className="text-xl font-semibold">{t("advisories:preview")}</h1>
        <span className="font-mono text-xs text-slate-500">{id}</span>
      </div>

      <pre className="bg-white rounded-md shadow-sm p-3 text-xs overflow-auto max-h-[60vh]">
        {JSON.stringify(csaf.data ?? {}, null, 2)}
      </pre>

      {confirmPublish ? (
        <div className="bg-amber-50 border border-amber-300 rounded-md p-4 space-y-3 max-w-xl">
          <p className="text-sm">{t("advisories:publish_warning")}</p>
          <div className="flex gap-2">
            <Button variant="danger" onClick={() => publish.mutate()} disabled={publish.isPending}>
              {t("common:actions.publish")}
            </Button>
            <Button variant="secondary" onClick={() => setConfirmPublish(false)}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </div>
      ) : confirmWithdraw ? (
        <div className="bg-red-50 border border-red-300 rounded-md p-4 space-y-3 max-w-xl">
          <p className="text-sm">{t("advisories:withdraw_warning")}</p>
          <div className="flex gap-2">
            <Button variant="danger" onClick={() => withdraw.mutate()} disabled={withdraw.isPending}>
              {t("common:actions.withdraw")}
            </Button>
            <Button variant="secondary" onClick={() => setConfirmWithdraw(false)}>
              {t("common:actions.cancel")}
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex gap-2">
          <Button onClick={() => setConfirmPublish(true)}>{t("common:actions.publish")}</Button>
          <Button variant="secondary" onClick={() => setConfirmWithdraw(true)}>{t("common:actions.withdraw")}</Button>
        </div>
      )}
    </div>
  );
}
