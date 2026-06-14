import clsx from "clsx";
import type { Scenario } from "@/api/scenarios";

interface Props {
  severity: Scenario["severity"];
}

const severityStyles: Record<Scenario["severity"], string> = {
  low: "bg-slate-100 text-slate-700",
  medium: "bg-yellow-100 text-yellow-800",
  high: "bg-orange-100 text-orange-800",
  critical: "bg-red-100 text-red-800",
};

export function SeverityBadge({ severity }: Props): JSX.Element {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize",
        severityStyles[severity],
      )}
    >
      {severity}
    </span>
  );
}
