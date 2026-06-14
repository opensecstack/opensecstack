import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { listRuns } from "@/api/results";
import { StatusBadge } from "@/components/StatusBadge";
import { Spinner } from "@/components/Spinner";
import { Button } from "@/components/Button";
import { formatTs, formatDuration } from "@/lib/format";

const PAGE_SIZE = 20;

export default function Results(): JSX.Element {
  const navigate = useNavigate();
  const [page, setPage] = useState(0);

  const { data, isLoading, error } = useQuery({
    queryKey: ["runs", PAGE_SIZE, page * PAGE_SIZE],
    queryFn: () => listRuns(PAGE_SIZE, page * PAGE_SIZE),
  });

  const runs = data?.runs ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / PAGE_SIZE);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-slate-900">Results</h2>

      {isLoading && (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      )}
      {error && <p className="text-sm text-red-600">Failed to load results.</p>}

      {!isLoading && (
        <div className="bg-white border border-slate-200 rounded-md shadow-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Run ID</th>
                <th className="px-4 py-2 text-left font-medium">Scenario</th>
                <th className="px-4 py-2 text-left font-medium">Environment</th>
                <th className="px-4 py-2 text-left font-medium">Status</th>
                <th className="px-4 py-2 text-left font-medium">Detected</th>
                <th className="px-4 py-2 text-left font-medium">Latency</th>
                <th className="px-4 py-2 text-left font-medium">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-slate-500">
                    No runs found.
                  </td>
                </tr>
              ) : (
                runs.map((run) => (
                  <tr
                    key={run.id}
                    className="hover:bg-slate-50 cursor-pointer"
                    onClick={() => navigate(`/results/${run.id}`)}
                  >
                    <td className="px-4 py-2 font-mono text-xs text-slate-600 truncate max-w-[100px]">
                      {run.id}
                    </td>
                    <td className="px-4 py-2 text-slate-700 font-mono text-xs">
                      {run.scenario_id}
                    </td>
                    <td className="px-4 py-2 text-slate-700 font-mono text-xs">
                      {run.environment_id}
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
      )}

      {totalPages > 1 && (
        <div className="flex items-center gap-3">
          <Button
            variant="secondary"
            disabled={page === 0}
            onClick={() => setPage((p) => p - 1)}
          >
            Previous
          </Button>
          <span className="text-sm text-slate-600">
            Page {page + 1} of {totalPages}
          </span>
          <Button
            variant="secondary"
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );
}
