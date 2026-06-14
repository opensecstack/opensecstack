import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listScenarios, type Scenario } from "@/api/scenarios";
import { ScenarioCard } from "@/components/ScenarioCard";
import { Spinner } from "@/components/Spinner";

const SEVERITY_OPTIONS: Array<Scenario["severity"] | "all"> = ["all", "low", "medium", "high", "critical"];

export default function Scenarios(): JSX.Element {
  const [severityFilter, setSeverityFilter] = useState<Scenario["severity"] | "all">("all");
  const [tagFilter, setTagFilter] = useState("");

  const { data: scenarios, isLoading, error } = useQuery({
    queryKey: ["scenarios"],
    queryFn: listScenarios,
  });

  const allTags = Array.from(
    new Set((scenarios ?? []).flatMap((s) => s.tags)),
  ).sort();

  const filtered = (scenarios ?? []).filter((s) => {
    if (severityFilter !== "all" && s.severity !== severityFilter) return false;
    if (tagFilter && !s.tags.includes(tagFilter)) return false;
    return true;
  });

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold text-slate-900">Scenarios</h2>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div>
          <label className="block text-xs font-medium text-slate-600 mb-1">Severity</label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as Scenario["severity"] | "all")}
            className="border border-slate-300 rounded-md px-2 py-1.5 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-400"
          >
            {SEVERITY_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s === "all" ? "All severities" : s.charAt(0).toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
        </div>
        {allTags.length > 0 && (
          <div>
            <label className="block text-xs font-medium text-slate-600 mb-1">Tag</label>
            <select
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              className="border border-slate-300 rounded-md px-2 py-1.5 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-400"
            >
              <option value="">All tags</option>
              {allTags.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {isLoading && (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      )}
      {error && (
        <p className="text-sm text-red-600">Failed to load scenarios.</p>
      )}
      {!isLoading && filtered.length === 0 && !error && (
        <p className="text-sm text-slate-500">No scenarios match the selected filters.</p>
      )}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {filtered.map((s) => (
          <ScenarioCard key={s.id} scenario={s} />
        ))}
      </div>
    </div>
  );
}
