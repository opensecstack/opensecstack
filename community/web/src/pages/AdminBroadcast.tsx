import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getBroadcast, createBroadcast, deleteBroadcast } from "@/api/admin";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";

export default function AdminBroadcast() {
  const role = useAuthStore((s) => s.role);
  const queryClient = useQueryClient();

  const [body, setBody] = useState("");
  const [linkUrl, setLinkUrl] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const { data: broadcastData, isLoading: broadcastLoading } = useQuery({
    queryKey: ["broadcast"],
    queryFn: getBroadcast,
    enabled: role === "admin",
  });

  const createMutation = useMutation({
    mutationFn: () =>
      createBroadcast(
        body,
        linkUrl.trim() || undefined,
        expiresAt ? new Date(expiresAt).toISOString() : undefined,
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast"] });
      setBody("");
      setLinkUrl("");
      setExpiresAt("");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteBroadcast(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["broadcast"] });
    },
  });

  if (role !== "admin") {
    return <p>Access denied.</p>;
  }

  const activeBroadcast = broadcastData?.broadcast ?? null;

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!body.trim()) return;
    createMutation.mutate();
  }

  return (
    <div className="max-w-2xl mx-auto mt-8 px-4 space-y-8">
      <h1 className="text-2xl font-bold text-gray-900">Broadcast</h1>

      {/* Create form */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h2 className="text-base font-semibold text-gray-800 mb-4">Create broadcast</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Message <span className="text-red-500">*</span>
            </label>
            <textarea
              rows={3}
              required
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Write your announcement here…"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/40 resize-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Link URL <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              type="url"
              value={linkUrl}
              onChange={(e) => setLinkUrl(e.target.value)}
              placeholder="https://example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Expires at <span className="text-gray-400 font-normal">(optional)</span>
            </label>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(e) => setExpiresAt(e.target.value)}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
          </div>

          {createMutation.isError && (
            <p className="text-sm text-red-600">Failed to create broadcast. Please try again.</p>
          )}

          <button
            type="submit"
            disabled={createMutation.isPending || !body.trim()}
            className="px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
          >
            {createMutation.isPending ? "Creating…" : "Create broadcast"}
          </button>
        </form>
      </div>

      {/* Active broadcast */}
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h2 className="text-base font-semibold text-gray-800 mb-4">Active broadcast</h2>

        {broadcastLoading && <p className="text-sm text-gray-500">Loading…</p>}

        {!broadcastLoading && !activeBroadcast && (
          <p className="text-sm text-gray-500">No active broadcast.</p>
        )}

        {activeBroadcast && (
          <div className="space-y-3">
            <p className="text-sm text-gray-800">{activeBroadcast.body}</p>

            {activeBroadcast.link_url && (
              <a
                href={activeBroadcast.link_url}
                target="_blank"
                rel="noreferrer"
                className="text-sm text-brand underline break-all"
              >
                {activeBroadcast.link_url}
              </a>
            )}

            <p className="text-xs text-gray-500">Created {timeAgo(activeBroadcast.created_at)}</p>

            <button
              onClick={() => deleteMutation.mutate(activeBroadcast.id)}
              disabled={deleteMutation.isPending}
              className="px-3 py-1.5 bg-red-600 text-white text-xs rounded-lg hover:bg-red-700 disabled:opacity-50 transition-colors"
            >
              {deleteMutation.isPending ? "Deactivating…" : "Deactivate"}
            </button>

            {deleteMutation.isError && (
              <p className="text-sm text-red-600">Failed to deactivate. Please try again.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
