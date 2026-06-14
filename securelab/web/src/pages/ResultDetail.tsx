import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getRun } from "@/api/results";
import { getScenario } from "@/api/scenarios";
import { AttackTimeline } from "@/components/AttackTimeline";
import { StatusBadge } from "@/components/StatusBadge";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Spinner } from "@/components/Spinner";
import { formatTs, formatDuration } from "@/lib/format";

function InfoRow({ label, value }: { label: string; value: React.ReactNode }): JSX.Element {
  return (
    <div className="flex gap-2 text-sm">
      <span className="w-40 shrink-0 font-medium text-slate-600">{label}</span>
      <span className="text-slate-900">{value}</span>
    </div>
  );
}

export default function ResultDetail(): JSX.Element {
  const { id } = useParams<{ id: string }>();

  const { data: run, isLoading: runLoading, error: runError } = useQuery({
    queryKey: ["run", id],
    queryFn: () => getRun(id!),
    enabled: !!id,
  });

  const { data: scenario } = useQuery({
    queryKey: ["scenario", run?.scenario_id],
    queryFn: () => getScenario(run!.scenario_id),
    enabled: !!run?.scenario_id,
  });

  if (runLoading) {
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );
  }

  if (runError || !run) {
    return <p className="text-sm text-red-600">Failed to load run details.</p>;
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="flex items-center gap-2 text-sm text-slate-500 mb-2">
          <Link to="/results" className="hover:underline">
            Results
          </Link>
          <span>/</span>
          <span className="font-mono">{run.id}</span>
        </div>
        <div className="flex items-center gap-3">
          <h2 className="text-lg font-semibold text-slate-900">Run Detail</h2>
          <StatusBadge status={run.status} />
        </div>
      </div>

      {/* Scenario info */}
      {scenario && (
        <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm space-y-2">
          <div className="flex items-center gap-3 mb-1">
            <h3 className="text-sm font-semibold text-slate-900">{scenario.name}</h3>
            <SeverityBadge severity={scenario.severity} />
          </div>
          {scenario.description && (
            <p className="text-sm text-slate-600">{scenario.description}</p>
          )}
          {scenario.mitre_technique_ids.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {scenario.mitre_technique_ids.map((tid) => (
                <span
                  key={tid}
                  className="inline-block bg-slate-100 text-slate-700 rounded px-1.5 py-0.5 text-xs font-mono"
                >
                  {tid}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Run summary */}
      <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm space-y-2">
        <h3 className="text-sm font-semibold text-slate-900 mb-3">Run Summary</h3>
        <InfoRow label="Run ID" value={<span className="font-mono text-xs">{run.id}</span>} />
        <InfoRow label="Environment" value={<span className="font-mono text-xs">{run.environment_id}</span>} />
        <InfoRow label="Status" value={<StatusBadge status={run.status} />} />
        <InfoRow
          label="Detected"
          value={run.detected == null ? "—" : run.detected ? "Yes" : "No"}
        />
        <InfoRow
          label="Detection Latency"
          value={formatDuration(run.detection_latency_ms)}
        />
        <InfoRow label="Started At" value={formatTs(run.started_at)} />
        <InfoRow label="Finished At" value={formatTs(run.finished_at)} />
        {run.notes && <InfoRow label="Notes" value={run.notes} />}
      </div>

      {/* Attack timeline */}
      {run.attack_events && run.attack_events.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm">
          <h3 className="text-sm font-semibold text-slate-900 mb-4">Attack Timeline</h3>
          <AttackTimeline events={run.attack_events} />
        </div>
      )}
    </div>
  );
}
