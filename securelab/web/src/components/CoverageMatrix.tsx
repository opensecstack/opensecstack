import clsx from "clsx";
import type { CoverageEntry } from "@/api/coverage";

interface Props {
  entries: CoverageEntry[];
}

type CellState = "detected" | "not_detected" | "not_tested";

function cellState(entry: CoverageEntry): CellState {
  if (entry.scenario_count === 0) return "not_tested";
  if (entry.detection_rate > 0) return "detected";
  return "not_detected";
}

const cellStyles: Record<CellState, string> = {
  detected: "bg-green-500 text-white",
  not_detected: "bg-red-400 text-white",
  not_tested: "bg-slate-200 text-slate-400",
};

const cellTitle: Record<CellState, string> = {
  detected: "Detected",
  not_detected: "Not detected",
  not_tested: "Not tested",
};

export function CoverageMatrix({ entries }: Props): JSX.Element {
  if (entries.length === 0) {
    return <p className="text-sm text-slate-500">No coverage data available.</p>;
  }

  // Group by tactic (column) then technique (row)
  const tactics = Array.from(new Set(entries.map((e) => e.tactic))).sort();
  const techniquesByTactic: Record<string, CoverageEntry[]> = {};
  for (const tactic of tactics) {
    techniquesByTactic[tactic] = entries.filter((e) => e.tactic === tactic);
  }

  const maxRows = Math.max(...Object.values(techniquesByTactic).map((a) => a.length));

  return (
    <div className="overflow-x-auto">
      <table className="border-separate border-spacing-0.5 min-w-max">
        <thead>
          <tr>
            {tactics.map((tactic) => (
              <th
                key={tactic}
                className="text-xs font-medium text-slate-700 text-center px-1 pb-1 capitalize whitespace-nowrap"
              >
                {tactic}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: maxRows }).map((_, rowIdx) => (
            <tr key={rowIdx}>
              {tactics.map((tactic) => {
                const entry = techniquesByTactic[tactic]?.[rowIdx];
                if (!entry) {
                  return <td key={tactic} className="w-24 h-7" />;
                }
                const state = cellState(entry);
                return (
                  <td key={tactic} className="w-24 h-7">
                    <div
                      className={clsx(
                        "h-full w-full rounded text-xs flex items-center justify-center cursor-default px-1 truncate",
                        cellStyles[state],
                      )}
                      title={`${entry.technique_id} — ${entry.technique_name}\n${cellTitle[state]}${state !== "not_tested" ? ` (${entry.detection_rate.toFixed(0)}%)` : ""}`}
                    >
                      {entry.technique_id}
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
