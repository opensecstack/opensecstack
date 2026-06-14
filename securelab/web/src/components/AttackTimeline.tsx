import clsx from "clsx";
import { formatTs } from "@/lib/format";
import type { AttackEvent } from "@/api/scenarios";

interface Props {
  events: AttackEvent[];
}

export function AttackTimeline({ events }: Props): JSX.Element {
  if (events.length === 0) {
    return <p className="text-sm text-slate-500">No attack events recorded.</p>;
  }

  return (
    <ol className="relative border-l border-slate-200 space-y-4 ml-3">
      {events.map((event, idx) => (
        <li key={idx} className="ml-4">
          <div
            className={clsx(
              "absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border-2 border-white",
              event.success ? "bg-green-500" : "bg-red-500",
            )}
          />
          <div className="bg-white border border-slate-200 rounded-md p-3 shadow-sm">
            <div className="flex items-center justify-between gap-4">
              <div>
                <span className="text-xs font-mono text-slate-500">{event.technique_id}</span>
                <p className="text-sm font-medium text-slate-900">{event.technique_name}</p>
              </div>
              <span
                className={clsx(
                  "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium",
                  event.success
                    ? "bg-green-100 text-green-800"
                    : "bg-red-100 text-red-800",
                )}
              >
                {event.success ? "Success" : "Failed"}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-500">{formatTs(event.timestamp)}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}
