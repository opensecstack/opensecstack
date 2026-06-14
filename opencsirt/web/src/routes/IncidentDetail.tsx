import { useParams } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useQuery } from "@tanstack/react-query";
import { Spinner } from "@/components/Spinner";
import { getIncident } from "@/api/incidents";
import { formatTs } from "@/lib/format";

export default function IncidentDetail(): JSX.Element {
  const { t } = useTranslation(["common", "incidents"]);
  const { id = "" } = useParams();
  const { data, isLoading, isError } = useQuery({
    queryKey: ["incident", id],
    queryFn: () => getIncident(id),
    enabled: !!id,
  });

  if (isLoading) return <Spinner />;
  if (isError || !data) return <p className="text-red-600">{t("common:labels.error")}</p>;

  return (
    <div className="space-y-4">
      <div className="bg-white rounded-md shadow-sm p-4 space-y-2">
        <h1 className="text-xl font-semibold">{data.title}</h1>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
          <Field label={t("incidents:fields.id")} value={<span className="font-mono">{data.id}</span>} />
          <Field label={t("incidents:fields.status")} value={t(`incidents:statuses.${data.status}`)} />
          <Field label={t("incidents:fields.severity")} value={data.severity} />
          <Field label={t("incidents:fields.source")} value={data.source} />
          <Field label={t("incidents:fields.created_at")} value={formatTs(data.created_at)} />
        </div>
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }): JSX.Element {
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div>{value}</div>
    </div>
  );
}
