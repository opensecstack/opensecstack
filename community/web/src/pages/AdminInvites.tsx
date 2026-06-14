import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { generateInvite, listInvites, type Invite } from "@/api/auth";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";

type InviteStatus = "Pending" | "Used" | "Expired";

function getStatus(invite: Invite): InviteStatus {
  if (invite.used_at !== null) return "Used";
  if (new Date(invite.expires_at) < new Date()) return "Expired";
  return "Pending";
}

const statusStyles: Record<InviteStatus, string> = {
  Pending: "bg-blue-100 text-blue-700",
  Used: "bg-gray-100 text-gray-600",
  Expired: "bg-red-100 text-red-700",
};

function CopyCode({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);

  function handleClick() {
    navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <span className="relative inline-flex items-center gap-1">
      <button
        onClick={handleClick}
        title="Click to copy"
        className="font-mono text-xs bg-gray-100 hover:bg-gray-200 transition-colors px-2 py-0.5 rounded cursor-pointer"
      >
        {code}
      </button>
      {copied && (
        <span className="absolute -top-6 left-0 text-xs bg-gray-800 text-white rounded px-1.5 py-0.5 whitespace-nowrap">
          Copied!
        </span>
      )}
    </span>
  );
}

export default function AdminInvites() {
  const role = useAuthStore((s) => s.role);
  const queryClient = useQueryClient();

  const { data: invites, isLoading, isError } = useQuery({
    queryKey: ["admin", "invites"],
    queryFn: listInvites,
    enabled: role === "moderator" || role === "admin",
  });

  const mutation = useMutation({
    mutationFn: generateInvite,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "invites"] });
    },
  });

  if (role === "viewer" || role === "author") {
    return (
      <div className="max-w-2xl mx-auto mt-12 px-4">
        <div className="bg-white border border-gray-200 rounded-lg p-8 text-center">
          <p className="text-gray-600 text-sm">
            Access denied — moderator role required.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-5xl mx-auto mt-8 px-4">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Invite Management</h1>
        <button
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
        >
          {mutation.isPending ? "Generating…" : "Generate invite"}
        </button>
      </div>

      {mutation.isError && (
        <div className="mb-4 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to generate invite. Please try again.
        </div>
      )}

      {isLoading && (
        <p className="text-sm text-gray-500">Loading invites…</p>
      )}

      {isError && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to load invites.
        </div>
      )}

      {invites && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          {invites.length === 0 ? (
            <p className="text-sm text-gray-500 p-6 text-center">
              No invites yet. Generate one to get started.
            </p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3">Code</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Expires</th>
                  <th className="px-4 py-3">Used by</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {invites.map((invite) => {
                  const status = getStatus(invite);
                  return (
                    <tr key={invite.id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-4 py-3">
                        <CopyCode code={invite.code} />
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${statusStyles[status]}`}
                        >
                          {status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {timeAgo(invite.created_at)}
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {timeAgo(invite.expires_at)}
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {invite.used_by_username ?? (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
