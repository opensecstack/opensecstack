import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getCoverage } from "@/api/coverage";
import { listScenarios } from "@/api/scenarios";
import { Spinner } from "@/components/Spinner";
import { formatPercent } from "@/lib/format";

export default function GapAnalysis(): JSX.Element {
  const navigate = useNavigate();

  const { data: coverageData, isLoading: coverageLoading } = useQuery({
    queryKey: ["coverage"],
    queryFn: getCoverage,
  });

  const { data: scenarios } = useQuery({
    queryKey: ["scenarios"],
    queryFn: listScenarios,
  });

  const gaps = (coverageData?.entries ?? [])
    .filter((e) => e.scenario_count > 0 && e.detection_rate < 50)
    .sort((a, b) => a.detection_rate - b.detection_rate);

  // Map technique_id -> scenario id for quick lookup
  const techniqueToScenario = new Map<string, string>();
  for (const scenario of scenarios ?? []) {
    for (const tid of scenario.mitre_technique_ids) {
      if (!techniqueToScenario.has(tid)) {
        techniqueToScenario.set(tid, scenario.id);
      }
    }
  }

  if (coverageLoading) {
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-slate-900">Gap Analysis</h2>
        <p className="text-sm text-slate-500 mt-1">
          Techniques with a detection rate below 50%, sorted by lowest detection rate first.
        </p>
      </div>

      {gaps.length === 0 && (
        <p className="text-sm text-slate-500">
          No gaps detected — all tested techniques have a detection rate of 50% or above.
        </p>
      )}

      {gaps.length > 0 && (
        <div className="bg-white border border-slate-200 rounded-md shadow-sm overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
              <tr>
                <th className="px-4 py-2 text-left font-medium">Technique ID</th>
                <th className="px-4 py-2 text-left font-medium">Name</th>
                <th className="px-4 py-2 text-left font-medium">Tactic</th>
                <th className="px-4 py-2 text-left font-medium">Scenarios</th>
                <th className="px-4 py-2 text-left font-medium">Detection Rate</th>
                <th className="px-4 py-2 text-left font-medium">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {gaps.map((entry) => {
                const scenarioId = techniqueToScenario.get(entry.technique_id);
                return (
                  <tr key={entry.technique_id} className="hover:bg-slate-50">
                    <td className="px-4 py-2 font-mono text-xs text-slate-700">
                      {entry.technique_id}
                    </td>
                    <td className="px-4 py-2 text-slate-900">{entry.technique_name}</td>
                    <td className="px-4 py-2 text-slate-600 capitalize">{entry.tactic}</td>
                    <td className="px-4 py-2 text-slate-700 text-center">{entry.scenario_count}</td>
                    <td className="px-4 py-2">
                      <span className="text-red-600 font-medium">
                        {formatPercent(entry.detection_rate)}
                      </span>
                    </td>
                    <td className="px-4 py-2">
                      {scenarioId ? (
                        <button
                          className="text-xs text-blue-600 hover:underline"
                          onClick={() => navigate(`/scenarios/${scenarioId}/run`)}
                        >
                          Run scenario
                        </button>
                      ) : (
                        <span className="text-xs text-slate-400">No scenario</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
