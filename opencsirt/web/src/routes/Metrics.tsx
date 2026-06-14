import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Spinner } from "@/components/Spinner";
import { fetchMetrics, type MetricsSnapshot } from "@/api/metrics";
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
          <Section title={t("metrics:sections.incidents")}>
            <MapCards map={snapshot.data.incidents_by_status} labelPrefix="metrics:incident_status." />
          </Section>
          <Section title={t("metrics:sections.advisories")}>
            <MapCards map={snapshot.data.advisories_by_state} labelPrefix="metrics:advisory_state." />
          </Section>
          <Section title={t("metrics:sections.system")}>
            <SystemCards data={snapshot.data} t={t} />
          </Section>
          <p className="text-xs text-slate-500">
            {t("metrics:source")} · {t("metrics:node")}: {snapshot.data.node} · v{snapshot.data.version} ·{" "}
            {formatTs(snapshot.data.snapshot_at)}
          </p>
        </>
      ) : null}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }): JSX.Element {
  return (
    <div className="space-y-2">
      <h2 className="text-sm font-semibold text-slate-600 uppercase tracking-wide">{title}</h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">{children}</div>
    </div>
  );
}

function MapCards({ map, labelPrefix }: { map: Record<string, number>; labelPrefix: string }): JSX.Element {
  const { t } = useTranslation(["metrics"]);
  const entries = Object.entries(map);
  if (entries.length === 0) {
    return <p className="col-span-4 text-sm text-slate-400">—</p>;
  }
  return (
    <>
      {entries.map(([key, val]) => (
        <Card key={key} label={t(`${labelPrefix}${key}`, key)} value={formatNumber(val)} />
      ))}
    </>
  );
}

function SystemCards({ data, t }: { data: MetricsSnapshot; t: (k: string) => string }): JSX.Element {
  return (
    <>
      <Card label={t("metrics:cards.outbox_pending")} value={formatNumber(data.outbox_pending)} />
      <Card label={t("metrics:cards.outbox_failed")} value={formatNumber(data.outbox_failed)} />
      <Card label={t("metrics:cards.iocs_last_bundle_size")} value={formatNumber(data.iocs_last_bundle_size)} />
      <Card
        label={t("metrics:cards.advisory_service_up")}
        value={data.advisory_service_up ? t("metrics:bool.yes") : t("metrics:bool.no")}
      />
    </>
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
