import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { fetchHealth, deriveOverall, type HealthLevel } from "@/api/health";

const dot: Record<HealthLevel | "unknown", string> = {
  ok: "bg-emerald-500",
  degraded: "bg-amber-500",
  down: "bg-red-500",
  unknown: "bg-slate-400",
};

export function HealthBadge(): JSX.Element {
  const { data, isError, isLoading } = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
    refetchInterval: 15_000,
    retry: 0,
  });

  const level: HealthLevel | "unknown" = isLoading
    ? "unknown"
    : deriveOverall(data, isError);

  const title = data
    ? `api:${data.status} db_ping:${data.db_ping} dataplane:${data.dataplane_attached} v${data.version}`
    : isError
      ? "API unreachable"
      : "checking…";

  return (
    <div
      title={title}
      aria-label={`health: ${level}`}
      className="flex items-center gap-1.5 text-xs text-slate-600"
    >
      <span className={clsx("inline-block h-2 w-2 rounded-full", dot[level])} />
      <span className="font-mono">{level}</span>
    </div>
  );
}
