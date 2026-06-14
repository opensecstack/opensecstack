import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getCoverage } from "@/api/coverage";
import { listRuns } from "@/api/results";
import { listScenarios } from "@/api/scenarios";
import { CoverageMatrix } from "@/components/CoverageMatrix";
import { StatusBadge } from "@/components/StatusBadge";
import { Spinner } from "@/components/Spinner";
import { formatTs, formatDuration, formatPercent } from "@/lib/format";

function StatCard({ label, value }: { label: string; value: string | number }): JSX.Element {
  return (
    <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className="text-2xl font-semibold text-slate-900">{value}</p>
    </div>
  );
}

export default function Dashboard(): JSX.Element {
  const navigate = useNavigate();

  const { data: scenarios } = useQuery({
    queryKey: ["scenarios"],
    queryFn: listScenarios,
    refetchInterval: 30_000,
  });

  const { data: runsData } = useQuery({
    queryKey: ["runs", 10, 0],
    queryFn: () => listRuns(10, 0),
    refetchInterval: 30_000,
  });

  const { data: coverageData, isLoading: coverageLoading } = useQuery({
    queryKey: ["coverage"],
    queryFn: getCoverage,
    refetchInterval: 30_000,
  });

  const now = Date.now();
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const runs = runsData?.runs ?? [];
  const runsThisWeek = runs.filter(
    (r) => r.started_at && now - new Date(r.started_at).getTime() < weekMs,
  ).length;

  const detectedRuns = runs.filter((r) => r.detected === true).length;
  const detectionRate = runs.length > 0 ? (detectedRuns / runs.length) * 100 : 0;

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-semibold text-slate-900">Dashboard</h2>

      {/* Summary cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Scenarios" value={scenarios?.length ?? "—"} />
        <StatCard label="Runs This Week" value={runsThisWeek} />
        <StatCard label="Detection Rate" value={runs.length > 0 ? formatPercent(detectionRate) : "—"} />
        <StatCard label="Avg Latency" value={
          (() => {
            const latencies = runs
              .filter((r) => r.detection_latency_ms != null)
              .map((r) => r.detection_latency_ms as number);
            if (latencies.length === 0) return "—";
            return formatDuration(Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length));
          })()
        } />
      </div>

      {/* Coverage heatmap */}
      <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm">
        <h3 className="text-sm font-semibold text-slate-900 mb-4">MITRE ATT&CK Coverage</h3>
        {coverageLoading ? (
          <div className="flex justify-center py-6">
            <Spinner />
          </div>
        ) : (
          <CoverageMatrix entries={coverageData?.entries ?? []} />
        )}
      </div>

      {/* Recent runs */}
      <div className="bg-white border border-slate-200 rounded-md shadow-sm">
        <div className="px-4 py-3 border-b border-slate-200">
          <h3 className="text-sm font-semibold text-slate-900">Recent Runs</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Run ID</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-left font-medium">Detected</th>
                <th className="px-4 py-2 text-left font-medium">Latency</th>
                <th className="px-4 py-2 text-left font-medium">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-4 text-center text-slate-500">
                    No runs yet.
                  </td>
                </tr>
              ) : (
                runs.map((run) => (
                  <tr
                    key={run.id}
                    className="hover:bg-slate-50 cursor-pointer"
                    onClick={() => navigate(`/results/${run.id}`)}
                  >
                    <td className="px-4 py-2 font-mono text-xs text-slate-600 truncate max-w-[120px]">
                      {run.id}
                    </td>
                    <td className="px-4 py-2">
                      <StatusBadge status={run.status} />
                    </td>
                    <td className="px-4 py-2 text-slate-700">
                      {run.detected == null ? "—" : run.detected ? "Yes" : "No"}
                    </td>
                    <td className="px-4 py-2 text-slate-700">
                      {formatDuration(run.detection_latency_ms)}
                    </td>
                    <td className="px-4 py-2 text-slate-500">{formatTs(run.started_at)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
