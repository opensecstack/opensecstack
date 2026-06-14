import { formatDuration } from "@/lib/format";

export interface LatencyEntry {
  technique_id: string;
  technique_name: string;
  latency_ms: number;
}

interface Props {
  entries: LatencyEntry[];
}

export function DetectionLatency({ entries }: Props): JSX.Element {
  if (entries.length === 0) {
    return <p className="text-sm text-slate-500">No latency data available.</p>;
  }

  const max = Math.max(...entries.map((e) => e.latency_ms), 1);

  return (
    <div className="space-y-2">
      {entries.map((entry) => {
        const pct = Math.round((entry.latency_ms / max) * 100);
        return (
          <div key={entry.technique_id}>
            <div className="flex items-center justify-between mb-0.5">
              <span className="text-xs text-slate-700 truncate max-w-[60%]">
                <span className="font-mono text-slate-500">{entry.technique_id}</span>{" "}
                {entry.technique_name}
              </span>
              <span className="text-xs font-medium text-slate-900">
                {formatDuration(entry.latency_ms)}
              </span>
            </div>
            <div className="w-full bg-slate-100 rounded-full h-2">
              <div
                className="bg-blue-500 h-2 rounded-full transition-all"
                style={{ width: `${pct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
