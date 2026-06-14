import { useParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { labStatus, startLab, stopLab } from "@/api/labs";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { LabTerminal } from "@/components/LabTerminal";

export default function LabRunner(): JSX.Element {
  const { id = "" } = useParams<{ id: string }>();
  const { t } = useTranslation("common");

  const status = useQuery({
    queryKey: ["lab", id, "status"],
    queryFn: () => labStatus(id),
    enabled: id.length > 0,
    retry: false,
  });
  const start = useMutation({ mutationFn: () => startLab(id) });
  const stop = useMutation({ mutationFn: () => stopLab(id) });

  const sessionId = start.data?.session_id;

  return (
    <section className="space-y-4">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">{t("labels.lab")}</h1>
        <div className="flex gap-2">
          <Button onClick={() => start.mutate()} disabled={start.isPending}>
            {start.isPending ? <Spinner /> : t("buttons.start")}
          </Button>
          <Button variant="secondary" onClick={() => stop.mutate()} disabled={stop.isPending}>
            {stop.isPending ? <Spinner /> : t("buttons.cancel")}
          </Button>
        </div>
      </header>
      {status.data && (
        <p className="text-xs text-slate-500">
          state: {status.data.state} · runtime: {status.data.runtime}
        </p>
      )}
      <LabTerminal sessionId={sessionId} />
    </section>
  );
}
