import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Spinner } from "@/components/Spinner";
import { fetchMetrics } from "@/api/metrics";
import { formatNumber, formatTs } from "@/lib/format";

export default function Metrics(): JSX.Element {
  const { t } = useTranslation(["common", "metrics"]);

  const snapshot = useQuery({
    queryKey: ["metrics-snapshot"],
    queryFn: fetchMetrics,
    refetchInterval: 10_000,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-semibold">{t("metrics:title")}</h1>
      {snapshot.isLoading ? (
        <Spinner />
      ) : snapshot.isError ? (
        <p className="text-red-600">{t("common:labels.error")}</p>
      ) : snapshot.data ? (
        <>
          {snapshot.data.dataplane_attached === false && (
            <div
              role="alert"
              className="rounded-md border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-800"
            >
              {t("metrics:dataplane_detached_warning")}
            </div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Card label={t("metrics:cards.pps_passed")} value={formatNumber(snapshot.data.pps_passed)} />
            <Card label={t("metrics:cards.pps_dropped")} value={formatNumber(snapshot.data.pps_dropped)} />
            <Card
              label={t("metrics:cards.pps_ratelimited")}
              value={formatNumber(snapshot.data.pps_ratelimited)}
            />
            <Card
              label={t("metrics:cards.syn_cookies_sent")}
              value={formatNumber(snapshot.data.syn_cookies_sent)}
            />
            <Card label={t("metrics:cards.rules_active")} value={formatNumber(snapshot.data.rules_active)} />
            <Card label={t("metrics:cards.rules_v4")} value={formatNumber(snapshot.data.rules_v4)} />
            <Card label={t("metrics:cards.rules_v6")} value={formatNumber(snapshot.data.rules_v6)} />
            <Card
              label={t("metrics:cards.rules_ratelimit")}
              value={formatNumber(snapshot.data.rules_ratelimit)}
            />
            <Card
              label={t("metrics:cards.rules_syncookie")}
              value={formatNumber(snapshot.data.rules_syncookie)}
            />
            <Card
              label={t("metrics:cards.ioc_pull_count")}
              value={formatNumber(snapshot.data.ioc_pull_count)}
            />
            <Card
              label={t("metrics:cards.ioc_pull_last_at")}
              value={snapshot.data.ioc_pull_last_at ? formatTs(snapshot.data.ioc_pull_last_at) : "—"}
            />
            <Card
              label={t("metrics:cards.citadel_queue_depth")}
              value={formatNumber(snapshot.data.citadel_queue_depth)}
            />
            <Card
              label={t("metrics:cards.dataplane_attached")}
              value={snapshot.data.dataplane_attached ? t("metrics:bool.yes") : t("metrics:bool.no")}
            />
            <Card
              label={t("metrics:cards.snapshot_at")}
              value={formatTs(snapshot.data.snapshot_at)}
            />
          </div>
        </>
      ) : null}
      <p className="text-xs text-slate-500">{t("metrics:source")}</p>
    </div>
  );
}

function Card({ label, value }: { label: string; value: string }): JSX.Element {
  return (
    <div className="bg-white rounded-md shadow-sm p-3">
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-lg font-mono">{value}</div>
    </div>
  );
}
