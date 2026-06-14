import { useQuery } from "@tanstack/react-query";
import { listAuditLog, type AuditEntry } from "@/api/audit";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";

const ACTION_LABELS: Record<string, string> = {
  lock_post: "Lock post",
  unlock_post: "Unlock post",
  pin_post: "Pin post",
  set_role: "Set role",
  resolve_report: "Resolve report",
};

function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

export default function AdminAudit() {
  const { role } = useAuthStore();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["audit-log"],
    queryFn: () => listAuditLog(),
    enabled: role === "admin",
  });

  if (role !== "admin") {
    return <p>Access denied.</p>;
  }

  return (
    <div className="max-w-6xl mx-auto mt-8 px-4">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Audit Log</h1>

      {isLoading && <p className="text-sm text-gray-500">Loading…</p>}

      {isError && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to load audit log.
        </div>
      )}

      {data && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          {data.entries.length === 0 ? (
            <p className="text-sm text-gray-500 p-6 text-center">No audit events yet.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Actor</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Target Type</th>
                  <th className="px-4 py-3">Target ID</th>
                  <th className="px-4 py-3">Note</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.entries.map((entry: AuditEntry) => (
                  <tr key={entry.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 text-gray-500 whitespace-nowrap">{timeAgo(entry.created_at)}</td>
                    <td className="px-4 py-3 font-medium text-gray-900">{entry.actor_username}</td>
                    <td className="px-4 py-3 text-gray-700">{actionLabel(entry.action)}</td>
                    <td className="px-4 py-3 text-gray-600">{entry.target_type}</td>
                    <td className="px-4 py-3 text-gray-500 font-mono text-xs">{entry.target_id || <span className="text-gray-300">—</span>}</td>
                    <td className="px-4 py-3 text-gray-600">{entry.note || <span className="text-gray-300">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
