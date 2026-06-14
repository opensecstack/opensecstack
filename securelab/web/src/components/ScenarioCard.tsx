import { useNavigate } from "react-router-dom";
import type { Scenario } from "@/api/scenarios";
import { SeverityBadge } from "./SeverityBadge";
import { Button } from "./Button";

interface Props {
  scenario: Scenario;
}

export function ScenarioCard({ scenario }: Props): JSX.Element {
  const navigate = useNavigate();

  return (
    <div className="bg-white border border-slate-200 rounded-md p-4 shadow-sm flex flex-col gap-3">
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-900 leading-snug">{scenario.name}</h3>
        <SeverityBadge severity={scenario.severity} />
      </div>
      {scenario.description && (
        <p className="text-xs text-slate-600 line-clamp-2">{scenario.description}</p>
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
      {scenario.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {scenario.tags.map((tag) => (
            <span
              key={tag}
              className="inline-block bg-blue-50 text-blue-700 rounded px-1.5 py-0.5 text-xs"
            >
              {tag}
            </span>
          ))}
        </div>
      )}
      <div className="mt-auto pt-1">
        <Button
          variant="primary"
          className="w-full"
          onClick={() => navigate(`/scenarios/${scenario.id}/run`)}
        >
          Run
        </Button>
      </div>
    </div>
  );
}
