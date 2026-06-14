import { useState, useEffect, useRef } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getScenario, runScenario } from "@/api/scenarios";
import { getRun } from "@/api/results";
import { listEnvironments } from "@/api/environments";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";
import { AttackTimeline } from "@/components/AttackTimeline";
import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { formatDuration } from "@/lib/format";

export default function RunScenario(): JSX.Element {
  const { id } = useParams<{ id: string }>();
  const [selectedEnv, setSelectedEnv] = useState("");
  const [runId, setRunId] = useState<string | null>(null);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: scenario, isLoading: scenarioLoading } = useQuery({
    queryKey: ["scenario", id],
    queryFn: () => getScenario(id!),
    enabled: !!id,
  });

  const { data: environments } = useQuery({
    queryKey: ["environments"],
    queryFn: listEnvironments,
  });

  const {
    data: runData,
    refetch: refetchRun,
  } = useQuery({
    queryKey: ["run", runId],
    queryFn: () => getRun(runId!),
    enabled: !!runId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "running" || status === "pending") return 3000;
      return false;
    },
  });

  // Set default environment when list loads
  useEffect(() => {
    if (environments && environments.length > 0 && !selectedEnv) {
      setSelectedEnv(environments[0].id);
    }
  }, [environments, selectedEnv]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, []);

  const isRunning =
    runData?.status === "running" || runData?.status === "pending";
  const isComplete =
    runData?.status === "passed" ||
    runData?.status === "failed" ||
    runData?.status === "error";

  async function handleRun(): Promise<void> {
    if (!id || !selectedEnv) return;
    setLaunching(true);
    setLaunchError(null);
    setRunId(null);
    try {
      const res = await runScenario(id, selectedEnv);
      setRunId(res.run_id);
      void refetchRun();
    } catch (err) {
      setLaunchError(err instanceof Error ? err.message : "Failed to start run.");
    } finally {
      setLaunching(false);
    }
  }

  if (scenarioLoading) {
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );
  }

  if (!scenario) {
    return <p className="text-sm text-red-600">Scenario not found.</p>;
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <div className="flex items-center gap-3 mb-1">
          <h2 className="text-lg font-semibold text-slate-900">{scenario.name}</h2>
          <SeverityBadge severity={scenario.severity} />
        </div>
        {scenario.description && (
          <p className="text-sm text-slate-600">{scenario.description}</p>
        )}
        {scenario.mitre_technique_ids.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
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

      {/* Run controls */}
      <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm space-y-3">
        <h3 className="text-sm font-semibold text-slate-900">Launch Run</h3>
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">Environment</label>
          <select
            value={selectedEnv}
            onChange={(e) => setSelectedEnv(e.target.value)}
            className="border border-slate-300 rounded-md px-2 py-1.5 text-sm text-slate-700 w-full focus:outline-none focus:ring-2 focus:ring-slate-400"
            disabled={!!runId && isRunning}
          >
            {environments?.map((env) => (
              <option key={env.id} value={env.id}>
                {env.name} ({env.kind}) — {env.status}
              </option>
            ))}
            {!environments?.length && (
              <option value="" disabled>
                No environments available
              </option>
            )}
          </select>
        </div>
        {launchError && <p className="text-sm text-red-600">{launchError}</p>}
        <Button
          onClick={() => void handleRun()}
          disabled={launching || (!!runId && isRunning) || !selectedEnv}
        >
          {launching ? "Starting…" : "Run Scenario"}
        </Button>
      </div>

      {/* Live run view */}
      {runData && (
        <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm space-y-4">
          <div className="flex items-center gap-3">
            <h3 className="text-sm font-semibold text-slate-900">Run Status</h3>
            <StatusBadge status={runData.status} />
            {isRunning && <Spinner />}
          </div>

          {isComplete && (
            <div className="rounded-md p-3 bg-slate-50 border border-slate-200 text-sm">
              <p>
                <span className="font-medium">Detected:</span>{" "}
                {runData.detected == null ? "—" : runData.detected ? "Yes" : "No"}
              </p>
              {runData.detection_latency_ms != null && (
                <p>
                  <span className="font-medium">Detection Latency:</span>{" "}
                  {formatDuration(runData.detection_latency_ms)}
                </p>
              )}
              {runData.notes && (
                <p>
                  <span className="font-medium">Notes:</span> {runData.notes}
                </p>
              )}
            </div>
          )}

          {runData.attack_events && runData.attack_events.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-slate-700 uppercase mb-3">Attack Timeline</h4>
              <AttackTimeline events={runData.attack_events} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
