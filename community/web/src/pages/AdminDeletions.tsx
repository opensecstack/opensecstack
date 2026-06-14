import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/state/auth";
import { apiClient } from "@/api/client";
import Spinner from "@/components/Spinner";
import { useState } from "react";

interface DeletionRequest {
  id: string;
  status: string;
  requested_at: string;
  scheduled_for: string;
  username: string;
  email: string;
  display_name: string;
}

async function listDeletionRequests(): Promise<{ requests: DeletionRequest[] }> {
  const r = await apiClient.get("/api/v1/admin/deletion-requests");
  return r.data;
}

async function processDeletion(id: string): Promise<void> {
  await apiClient.post(`/api/v1/admin/deletion-requests/${id}/process`);
}

export default function AdminDeletions() {
  const { token, role } = useAuthStore();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [processing, setProcessing] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<string | null>(null);

  if (!token || role !== "admin") {
    navigate("/", { replace: true });
    return null;
  }

  const { data, isLoading } = useQuery({
    queryKey: ["admin-deletions"],
    queryFn: listDeletionRequests,
  });

  async function handleProcess(id: string) {
    if (confirming !== id) { setConfirming(id); return; }
    setProcessing(id);
    setConfirming(null);
    try {
      await processDeletion(id);
      qc.invalidateQueries({ queryKey: ["admin-deletions"] });
    } finally {
      setProcessing(null);
    }
  }

  const requests = data?.requests ?? [];

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">GDPR Deletion Requests</h1>

      {isLoading ? (
        <Spinner />
      ) : requests.length === 0 ? (
        <div className="bg-white border border-gray-200 rounded-lg p-8 text-center text-gray-400">
          No pending deletion requests.
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr>
                <th className="text-left px-4 py-3 font-medium text-gray-600">User</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Requested</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Scheduled for</th>
                <th className="text-left px-4 py-3 font-medium text-gray-600">Status</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {requests.map((req) => {
                const isOverdue = new Date(req.scheduled_for) <= new Date();
                return (
                  <tr key={req.id} className={isOverdue ? "bg-red-50" : ""}>
                    <td className="px-4 py-3">
                      <p className="font-medium text-gray-900">{req.username}</p>
                      <p className="text-xs text-gray-400">{req.display_name}</p>
                    </td>
                    <td className="px-4 py-3 text-gray-600">
                      {new Date(req.requested_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3">
                      <span className={isOverdue ? "text-red-600 font-medium" : "text-gray-600"}>
                        {new Date(req.scheduled_for).toLocaleDateString()}
                        {isOverdue && " (overdue)"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 bg-amber-100 text-amber-700 rounded text-xs font-medium">
                        {req.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-2">
                        {confirming === req.id && (
                          <button
                            onClick={() => setConfirming(null)}
                            className="text-xs text-gray-400 hover:text-gray-600"
                          >
                            Cancel
                          </button>
                        )}
                        <button
                          onClick={() => handleProcess(req.id)}
                          disabled={processing === req.id}
                          className={`px-3 py-1.5 text-xs rounded-lg transition-colors disabled:opacity-50 ${
                            confirming === req.id
                              ? "bg-red-600 text-white hover:bg-red-700"
                              : "border border-red-300 text-red-600 hover:bg-red-50"
                          }`}
                        >
                          {processing === req.id
                            ? "Deleting…"
                            : confirming === req.id
                            ? "Confirm delete"
                            : "Process now"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="mt-4 text-xs text-gray-400">
        Overdue requests are also processed automatically by the scheduler every minute.
      </p>
    </div>
  );
}
