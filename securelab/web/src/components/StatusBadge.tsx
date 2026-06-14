import clsx from "clsx";
import type { ScenarioRun } from "@/api/scenarios";

interface Props {
  status: ScenarioRun["status"];
}

const statusStyles: Record<ScenarioRun["status"], string> = {
  pending: "bg-slate-100 text-slate-700",
  running: "bg-blue-100 text-blue-800",
  passed: "bg-green-100 text-green-800",
  failed: "bg-red-100 text-red-800",
  error: "bg-red-100 text-red-800",
};

export function StatusBadge({ status }: Props): JSX.Element {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize",
        statusStyles[status],
      )}
    >
      {status}
    </span>
  );
}
