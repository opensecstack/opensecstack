import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listSessions, revokeSession, revokeAllSessions } from "@/api/sessions";

function formatDate(iso: string) {
  return new Date(iso).toLocaleString();
}

export default function ActiveSessionsSection() {
  const qc = useQueryClient();

  const { data: sessions, isLoading: sessionsLoading } = useQuery({
    queryKey: ["sessions"],
    queryFn: listSessions,
  });

  const revokeMut = useMutation({
    mutationFn: revokeSession,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const revokeAllMut = useMutation({
    mutationFn: revokeAllSessions,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const nonCurrentCount = sessions?.filter((s) => !s.is_current).length ?? 0;

  return (
    <div className="mt-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
      <div className="flex items-center justify-between mb-1">
        <h2 className="font-semibold">Active Sessions</h2>
        {nonCurrentCount > 0 && (
          <button
            onClick={() => revokeAllMut.mutate()}
            disabled={revokeAllMut.isPending}
            className="text-xs text-red-600 hover:underline disabled:opacity-50"
          >
            {revokeAllMut.isPending ? "Revoking…" : "Revoke all other sessions"}
          </button>
        )}
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Devices and browsers that are currently signed into your account.
      </p>

      {sessionsLoading ? (
        <div className="space-y-3">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-16 rounded-md bg-gray-100 dark:bg-gray-800 animate-pulse" />
          ))}
        </div>
      ) : !sessions || sessions.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No active sessions found.</p>
      ) : (
        <ul className="space-y-3">
          {sessions.map((s) => (
            <li
              key={s.id}
              className="flex items-start justify-between gap-4 border border-gray-100 dark:border-gray-800 rounded-md px-4 py-3"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                    {s.device_info || "Unknown device"}
                  </span>
                  {s.is_current && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-400">
                      Current
                    </span>
                  )}
                </div>
                <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-gray-500 dark:text-gray-400">
                  <span>{s.ip_address || "Unknown IP"}</span>
                  <span>Created {formatDate(s.created_at)}</span>
                  <span>Last active {formatDate(s.last_seen_at)}</span>
                </div>
              </div>
              {!s.is_current && (
                <button
                  onClick={() => revokeMut.mutate(s.id)}
                  disabled={revokeMut.isPending && revokeMut.variables === s.id}
                  className="shrink-0 text-xs text-red-600 hover:underline disabled:opacity-50"
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
