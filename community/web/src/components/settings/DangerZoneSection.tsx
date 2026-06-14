import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getDeletionStatus, requestDeletion, cancelDeletion, exportMyData } from "@/api/gdpr";
import { useAuthStore } from "@/state/auth";

export default function DangerZoneSection() {
  const { token } = useAuthStore();
  const queryClient = useQueryClient();

  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deletionMsg, setDeletionMsg] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const { data: deletionData } = useQuery({
    queryKey: ["deletion-status"],
    queryFn: getDeletionStatus,
    enabled: !!token,
  });

  const pendingRequest = deletionData?.request ?? null;

  const requestMutation = useMutation({
    mutationFn: requestDeletion,
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["deletion-status"] });
      setShowDeleteConfirm(false);
      setDeletionMsg(`Deletion scheduled for ${new Date(data.scheduled_for).toLocaleDateString()}.`);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: cancelDeletion,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["deletion-status"] });
      setDeletionMsg("Deletion cancelled.");
    },
  });

  async function handleExport() {
    setExporting(true);
    setExportError(null);
    try {
      const blob = await exportMyData();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "my-data.json";
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      setExportError(err instanceof Error ? err.message : "Export failed. Please try again.");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="mt-10 bg-white dark:bg-gray-900 border border-red-200 dark:border-red-900 rounded-lg p-6">
      <h2 className="font-semibold text-red-700 mb-1">Danger zone</h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Requesting deletion will permanently remove your account and all content after 30 days.
        You can cancel at any time before then.
      </p>

      {/* Download my data */}
      <div className="mb-6 pb-6 border-b border-gray-100 dark:border-gray-800">
        <p className="text-sm text-gray-700 dark:text-gray-300 mb-2">
          Download a copy of all your data (profile, posts, comments, follows, bookmarks) before
          deleting your account.
        </p>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm rounded-md hover:bg-gray-50 dark:hover:bg-gray-800 disabled:opacity-50"
        >
          {exporting ? "Downloading…" : "Download my data"}
        </button>
        {exportError && (
          <p className="mt-2 text-sm text-red-500">{exportError}</p>
        )}
      </div>

      {deletionMsg && (
        <p className="mb-4 text-sm text-gray-700 dark:text-gray-300 bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md px-3 py-2">
          {deletionMsg}
        </p>
      )}

      {pendingRequest ? (
        <div className="flex items-center gap-4 flex-wrap">
          <p className="text-sm text-red-600">
            Deletion scheduled for{" "}
            <strong>{new Date(pendingRequest.scheduled_for).toLocaleDateString()}</strong>.
          </p>
          <button
            onClick={() => cancelMutation.mutate()}
            disabled={cancelMutation.isPending}
            className="px-4 py-2 border border-red-300 text-red-600 text-sm rounded-md hover:bg-red-50 disabled:opacity-50"
          >
            {cancelMutation.isPending ? "Cancelling…" : "Cancel deletion"}
          </button>
        </div>
      ) : showDeleteConfirm ? (
        <div className="flex items-center gap-3 flex-wrap">
          <p className="text-sm text-gray-700 dark:text-gray-300">Are you sure? This cannot be undone after 30 days.</p>
          <button
            onClick={() => requestMutation.mutate()}
            disabled={requestMutation.isPending}
            className="px-4 py-2 bg-red-600 text-white text-sm rounded-md hover:bg-red-700 disabled:opacity-50"
          >
            {requestMutation.isPending ? "Requesting…" : "Yes, delete my account"}
          </button>
          <button
            onClick={() => setShowDeleteConfirm(false)}
            className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 text-sm rounded-md hover:bg-gray-50 dark:hover:bg-gray-800"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setShowDeleteConfirm(true)}
          className="px-4 py-2 border border-red-300 text-red-600 text-sm rounded-md hover:bg-red-50"
        >
          Request account deletion
        </button>
      )}
    </div>
  );
}
