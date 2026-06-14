import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  listAPIKeys,
  createAPIKey,
  deleteAPIKey,
  type ApiKeyCreateResponse,
} from "@/api/apiKeys";

export default function ApiKeysPanel() {
  const queryClient = useQueryClient();

  const [keyName, setKeyName] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  // Holds the full key immediately after creation — never persisted beyond this render cycle
  const [newKey, setNewKey] = useState<ApiKeyCreateResponse | null>(null);
  const [copied, setCopied] = useState(false);

  // id of the key currently awaiting revoke confirmation
  const [confirmRevoke, setConfirmRevoke] = useState<number | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["api-keys"],
    queryFn: listAPIKeys,
  });

  const createMutation = useMutation({
    mutationFn: (name: string) => createAPIKey(name),
    onSuccess: (created) => {
      setNewKey(created);
      setKeyName("");
      setCreateError(null);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: () => {
      setCreateError("Failed to create key. Please try again.");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteAPIKey(id),
    onSuccess: () => {
      setConfirmRevoke(null);
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: () => {
      setConfirmRevoke(null);
    },
  });

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = keyName.trim();
    if (!trimmed) {
      setCreateError("Key name is required.");
      return;
    }
    setCreateError(null);
    createMutation.mutate(trimmed);
  }

  function handleCopy() {
    if (!newKey) return;
    navigator.clipboard.writeText(newKey.key).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  function handleRevoke(id: number) {
    if (confirmRevoke === id) {
      deleteMutation.mutate(id);
    } else {
      setConfirmRevoke(id);
    }
  }

  const keys = data?.keys ?? [];

  return (
    <div className="space-y-5">
      <p className="text-sm text-gray-500 dark:text-gray-400">
        Generate personal access tokens for use with the SIN API.
      </p>

      {/* One-time key reveal */}
      {newKey && (
        <div className="rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-4 space-y-3">
          <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
            Copy this key now — it won't be shown again.
          </p>
          <div className="flex items-center gap-2">
            <code className="flex-1 break-all rounded border border-amber-200 dark:border-amber-800 bg-white dark:bg-gray-900 px-3 py-2 text-xs font-mono text-gray-900 dark:text-gray-100 select-all">
              {newKey.key}
            </code>
            <button
              type="button"
              onClick={handleCopy}
              className="shrink-0 rounded bg-amber-600 hover:bg-amber-700 px-3 py-2 text-xs font-medium text-white transition-colors"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <button
            type="button"
            onClick={() => { setNewKey(null); setCopied(false); }}
            className="text-xs text-amber-700 dark:text-amber-400 hover:underline"
          >
            Done
          </button>
        </div>
      )}

      {/* Create form */}
      <form onSubmit={handleCreate} className="flex gap-2">
        <input
          type="text"
          value={keyName}
          onChange={(e) => setKeyName(e.target.value)}
          placeholder="Key name, e.g. CI script"
          className="flex-1 rounded-md border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-800 px-3 py-2 text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/50"
        />
        <button
          type="submit"
          disabled={createMutation.isPending || !keyName.trim()}
          className="shrink-0 rounded-md bg-brand px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-50 transition-opacity"
        >
          {createMutation.isPending ? "Generating…" : "Generate"}
        </button>
      </form>
      {createError && (
        <p className="text-xs text-red-500">{createError}</p>
      )}

      {/* Key list */}
      {isLoading ? (
        <div className="divide-y divide-gray-100 dark:divide-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          {[0, 1, 2].map((i) => (
            <div key={i} className="flex items-center justify-between px-4 py-3 animate-pulse">
              <div className="space-y-1.5">
                <div className="h-3.5 w-32 rounded bg-gray-200 dark:bg-gray-700" />
                <div className="h-3 w-24 rounded bg-gray-100 dark:bg-gray-800" />
              </div>
              <div className="h-6 w-14 rounded bg-gray-200 dark:bg-gray-700" />
            </div>
          ))}
        </div>
      ) : keys.length === 0 ? (
        <p className="text-sm italic text-gray-500 dark:text-gray-400">No API keys yet.</p>
      ) : (
        <div className="divide-y divide-gray-100 dark:divide-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          {keys.map((k) => (
            <div key={k.id} className="flex items-center justify-between gap-4 px-4 py-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-gray-900 dark:text-gray-100">
                  {k.name}
                </p>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Created {new Date(k.created_at).toLocaleDateString()}
                  {k.last_used_at
                    ? ` · Last used ${new Date(k.last_used_at).toLocaleDateString()}`
                    : " · Never used"}
                </p>
              </div>
              <button
                type="button"
                disabled={deleteMutation.isPending && confirmRevoke === k.id}
                onClick={() => handleRevoke(k.id)}
                onBlur={() => {
                  // Reset confirmation if focus leaves without confirming
                  if (confirmRevoke === k.id) {
                    setTimeout(() => setConfirmRevoke((prev) => (prev === k.id ? null : prev)), 150);
                  }
                }}
                className={
                  confirmRevoke === k.id
                    ? "shrink-0 rounded px-3 py-1 text-xs font-medium bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 transition-colors"
                    : "shrink-0 rounded px-3 py-1 text-xs font-medium border border-red-300 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                }
              >
                {confirmRevoke === k.id
                  ? (deleteMutation.isPending ? "Revoking…" : "Confirm revoke?")
                  : "Revoke"}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
