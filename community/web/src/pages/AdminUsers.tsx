import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  listAdminUsers,
  setUserRole,
  deactivateUser,
  reactivateUser,
  bulkSetRole,
  bulkBanUsers,
  setUserBadge,
  removeUserBadge,
  listModNotes,
  createModNote,
  deleteModNote,
  type AdminUser,
  type ModNote,
} from "@/api/admin";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";

const ROLES = ["viewer", "author", "moderator", "admin"] as const;
type Role = (typeof ROLES)[number];

const BADGES = ["Staff", "Moderator", "Top Contributor", "Verified", "Alumni"] as const;
type Badge = (typeof BADGES)[number];

const badgeChipStyles: Record<Badge, string> = {
  Staff: "bg-indigo-100 text-indigo-700",
  Moderator: "bg-purple-100 text-purple-700",
  "Top Contributor": "bg-amber-100 text-amber-700",
  Verified: "bg-green-100 text-green-700",
  Alumni: "bg-gray-100 text-gray-600",
};

function BadgeChip({ badge }: { badge: string }) {
  const cls = badgeChipStyles[badge as Badge] ?? "bg-gray-100 text-gray-600";
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
      {badge}
    </span>
  );
}

const roleBadgeStyles: Record<Role, string> = {
  viewer: "bg-gray-100 text-gray-600",
  author: "bg-blue-100 text-blue-700",
  moderator: "bg-yellow-100 text-yellow-700",
  admin: "bg-red-100 text-red-700",
};

function RoleBadge({ role }: { role: string }) {
  const cls = roleBadgeStyles[role as Role] ?? "bg-gray-100 text-gray-600";
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
      {role}
    </span>
  );
}

// ModeratorNotes is a collapsible panel showing notes for a single user.
function ModeratorNotes({ username }: { username: string }) {
  const queryClient = useQueryClient();
  const [newBody, setNewBody] = useState("");

  const { data: notes = [], isLoading } = useQuery<ModNote[]>({
    queryKey: ["mod-notes", username],
    queryFn: () => listModNotes(username),
  });

  const createMutation = useMutation({
    mutationFn: () => createModNote(username, newBody.trim()),
    onSuccess: () => {
      setNewBody("");
      queryClient.invalidateQueries({ queryKey: ["mod-notes", username] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteModNote(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mod-notes", username] });
    },
  });

  return (
    <div className="px-4 py-3 bg-amber-50 border-t border-amber-100">
      <p className="text-xs font-semibold text-amber-800 mb-2 uppercase tracking-wide">
        Moderator Notes
      </p>

      {isLoading && <p className="text-xs text-gray-400">Loading…</p>}

      {notes.length === 0 && !isLoading && (
        <p className="text-xs text-gray-400 mb-2">No notes yet.</p>
      )}

      {notes.length > 0 && (
        <ul className="mb-3 space-y-2">
          {notes.map((note) => (
            <li key={note.id} className="flex items-start gap-2 text-xs">
              <div className="flex-1 rounded bg-white border border-amber-200 px-3 py-2">
                <p className="text-gray-800 whitespace-pre-wrap">{note.body}</p>
                <p className="mt-1 text-gray-400">
                  by <span className="font-medium text-gray-600">{note.author_username}</span>{" "}
                  &middot; {timeAgo(note.created_at)}
                </p>
              </div>
              <button
                onClick={() => deleteMutation.mutate(note.id)}
                disabled={deleteMutation.isPending}
                title="Delete note"
                className="mt-1 text-gray-400 hover:text-red-500 transition-colors disabled:opacity-40"
              >
                {/* trash icon */}
                <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
              </button>
            </li>
          ))}
        </ul>
      )}

      <div className="flex items-start gap-2">
        <textarea
          value={newBody}
          onChange={(e) => setNewBody(e.target.value)}
          placeholder="Add a private note…"
          rows={2}
          className="flex-1 text-xs border border-amber-300 rounded px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-amber-400 resize-none"
        />
        <button
          onClick={() => createMutation.mutate()}
          disabled={createMutation.isPending || newBody.trim() === ""}
          className="text-xs rounded px-3 py-1.5 bg-amber-600 text-white hover:bg-amber-700 disabled:opacity-50 transition-colors self-end"
        >
          Add Note
        </button>
      </div>

      {createMutation.isError && (
        <p className="mt-1 text-xs text-red-500">Failed to add note.</p>
      )}
    </div>
  );
}

export default function AdminUsers() {
  const { role: myRole, username: myUsername } = useAuthStore();
  const queryClient = useQueryClient();
  const [confirmDeactivate, setConfirmDeactivate] = useState<string | null>(null);
  const [expandedNotes, setExpandedNotes] = useState<Set<string>>(new Set());

  function toggleNotes(username: string) {
    setExpandedNotes((prev) => {
      const next = new Set(prev);
      if (next.has(username)) {
        next.delete(username);
      } else {
        next.add(username);
      }
      return next;
    });
  }

  // Bulk selection state
  const [selectedUsernames, setSelectedUsernames] = useState<Set<string>>(new Set());
  const [bulkRole, setBulkRole] = useState<string>("moderator");
  const [bulkSuccessMsg, setBulkSuccessMsg] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["admin-users"],
    queryFn: () => listAdminUsers(50, 0),
    enabled: myRole === "admin",
  });

  const mutation = useMutation({
    mutationFn: ({ username, role }: { username: string; role: string }) =>
      setUserRole(username, role),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  const deactivateMutation = useMutation({
    mutationFn: (username: string) => deactivateUser(username),
    onSuccess: () => {
      setConfirmDeactivate(null);
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  const reactivateMutation = useMutation({
    mutationFn: (username: string) => reactivateUser(username),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  const bulkRoleMutation = useMutation({
    mutationFn: ({ usernames, role }: { usernames: string[]; role: string }) =>
      bulkSetRole(usernames, role),
    onSuccess: (result) => {
      setBulkSuccessMsg(`Role updated for ${result.updated} user(s).`);
      setSelectedUsernames(new Set());
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  const bulkBanMutation = useMutation({
    mutationFn: ({ usernames, banned }: { usernames: string[]; banned: boolean }) =>
      bulkBanUsers(usernames, banned),
    onSuccess: (result, variables) => {
      const action = variables.banned ? "Banned" : "Unbanned";
      setBulkSuccessMsg(`${action} ${result.updated} user(s).`);
      setSelectedUsernames(new Set());
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  const badgeMutation = useMutation({
    mutationFn: ({ username, badge }: { username: string; badge: string | null }) =>
      badge ? setUserBadge(username, badge) : removeUserBadge(username),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin-users"] });
    },
  });

  if (myRole !== "admin") {
    return <p>Access denied.</p>;
  }

  const users = data?.users ?? [];
  const selectableUsernames = users
    .filter((u) => u.username !== myUsername)
    .map((u) => u.username);
  const allSelected =
    selectableUsernames.length > 0 &&
    selectableUsernames.every((u) => selectedUsernames.has(u));

  function toggleAll() {
    if (allSelected) {
      setSelectedUsernames(new Set());
    } else {
      setSelectedUsernames(new Set(selectableUsernames));
    }
  }

  function toggleUser(username: string) {
    setSelectedUsernames((prev) => {
      const next = new Set(prev);
      if (next.has(username)) {
        next.delete(username);
      } else {
        next.add(username);
      }
      return next;
    });
  }

  const selectionArray = Array.from(selectedUsernames);
  const isBulkPending =
    bulkRoleMutation.isPending || bulkBanMutation.isPending;

  function handleBulkRole() {
    if (selectionArray.length === 0) return;
    setBulkSuccessMsg(null);
    bulkRoleMutation.mutate({ usernames: selectionArray, role: bulkRole });
  }

  function handleBulkBan(banned: boolean) {
    if (selectionArray.length === 0) return;
    setBulkSuccessMsg(null);
    bulkBanMutation.mutate({ usernames: selectionArray, banned });
  }

  return (
    <div className="max-w-6xl mx-auto mt-8 px-4">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">User Management</h1>

      {(mutation.isError ||
        deactivateMutation.isError ||
        reactivateMutation.isError ||
        bulkRoleMutation.isError ||
        bulkBanMutation.isError) && (
        <div className="mb-4 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Action failed. Please try again.
        </div>
      )}

      {bulkSuccessMsg && (
        <div className="mb-4 rounded-md bg-green-50 border border-green-200 px-4 py-3 text-sm text-green-700">
          {bulkSuccessMsg}
        </div>
      )}

      {isLoading && <p className="text-sm text-gray-500">Loading users…</p>}

      {isError && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to load users.
        </div>
      )}

      {/* Bulk action toolbar — slides in when rows are selected */}
      {selectedUsernames.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-3 rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-3 shadow-sm transition-all dark:border-indigo-800 dark:bg-indigo-950">
          <span className="text-sm font-medium text-indigo-800 dark:text-indigo-200">
            {selectedUsernames.size} user{selectedUsernames.size !== 1 ? "s" : ""} selected
          </span>

          {/* Set role */}
          <div className="flex items-center gap-2">
            <select
              value={bulkRole}
              disabled={isBulkPending}
              onChange={(e) => setBulkRole(e.target.value)}
              className="text-xs border border-indigo-300 rounded px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 disabled:opacity-50 bg-white dark:bg-indigo-900 dark:border-indigo-600 dark:text-indigo-100"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
            <button
              onClick={handleBulkRole}
              disabled={isBulkPending}
              className="text-xs rounded px-3 py-1.5 bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              Set role
            </button>
          </div>

          {/* Ban / Unban */}
          <button
            onClick={() => handleBulkBan(true)}
            disabled={isBulkPending}
            className="text-xs rounded px-3 py-1.5 bg-red-600 text-white hover:bg-red-700 disabled:opacity-50 transition-colors"
          >
            Ban selected
          </button>
          <button
            onClick={() => handleBulkBan(false)}
            disabled={isBulkPending}
            className="text-xs rounded px-3 py-1.5 border border-gray-400 text-gray-700 hover:bg-gray-100 disabled:opacity-50 transition-colors dark:text-gray-200 dark:border-gray-500 dark:hover:bg-indigo-900"
          >
            Unban selected
          </button>

          {/* Clear */}
          <button
            onClick={() => {
              setSelectedUsernames(new Set());
              setBulkSuccessMsg(null);
            }}
            className="ml-auto text-xs rounded px-2 py-1.5 text-indigo-600 hover:text-indigo-800 hover:bg-indigo-100 transition-colors dark:text-indigo-300 dark:hover:bg-indigo-800"
            title="Clear selection"
          >
            ✕ Clear
          </button>
        </div>
      )}

      {data && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          {users.length === 0 ? (
            <p className="text-sm text-gray-500 p-6 text-center">No users found.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3 w-8">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={toggleAll}
                      aria-label="Select all users"
                      className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                    />
                  </th>
                  <th className="px-4 py-3">Username</th>
                  <th className="px-4 py-3">Display name</th>
                  <th className="px-4 py-3">Email</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Badge</th>
                  <th className="px-4 py-3">Posts</th>
                  <th className="px-4 py-3">Joined</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Notes</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {users.map((user: AdminUser) => {
                  const isMe = user.username === myUsername;
                  const isDeactivated = !!user.deactivated_at;
                  const isSelected = selectedUsernames.has(user.username);
                  const notesOpen = expandedNotes.has(user.username);
                  return (
                    <>
                    <tr
                      key={user.id}
                      className={`transition-colors ${
                        isSelected
                          ? "bg-indigo-50 dark:bg-indigo-950"
                          : isDeactivated
                          ? "bg-gray-50 opacity-60"
                          : isMe
                          ? "bg-gray-50"
                          : "hover:bg-gray-50"
                      }`}
                    >
                      <td className="px-4 py-3">
                        {!isMe && (
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => toggleUser(user.username)}
                            aria-label={`Select ${user.username}`}
                            className="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                          />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          to={`/users/${user.username}`}
                          className="text-brand hover:underline font-medium"
                        >
                          {user.username}
                        </Link>
                        {isMe && (
                          <span className="ml-2 text-xs text-gray-400">(you)</span>
                        )}
                        {isDeactivated && (
                          <span className="ml-2 inline-block rounded-full bg-gray-200 text-gray-500 px-2 py-0.5 text-xs font-medium">
                            deactivated
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-gray-700">
                        {user.display_name || <span className="text-gray-400">—</span>}
                      </td>
                      <td className="px-4 py-3 text-gray-600">
                        {user.email ?? <span className="text-gray-400">—</span>}
                      </td>
                      <td className="px-4 py-3">
                        {isMe ? (
                          <RoleBadge role={user.role} />
                        ) : (
                          <select
                            value={user.role}
                            disabled={mutation.isPending || isDeactivated}
                            onChange={(e) =>
                              mutation.mutate({ username: user.username, role: e.target.value })
                            }
                            className="text-xs border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:opacity-50"
                          >
                            {ROLES.map((r) => (
                              <option key={r} value={r}>
                                {r}
                              </option>
                            ))}
                          </select>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2 flex-wrap">
                          {user.platform_badge && <BadgeChip badge={user.platform_badge} />}
                          {!isMe && (
                            <select
                              value=""
                              disabled={badgeMutation.isPending}
                              onChange={(e) => {
                                const val = e.target.value;
                                badgeMutation.mutate({
                                  username: user.username,
                                  badge: val === "__remove__" ? null : val,
                                });
                                e.target.value = "";
                              }}
                              className="text-xs border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-brand/40 disabled:opacity-50"
                            >
                              <option value="" disabled>Set badge…</option>
                              {BADGES.map((b) => (
                                <option key={b} value={b}>{b}</option>
                              ))}
                              <option value="__remove__">— Remove badge</option>
                            </select>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-600">{user.post_count}</td>
                      <td className="px-4 py-3 text-gray-500">{timeAgo(user.created_at)}</td>
                      <td className="px-4 py-3">
                        {!isMe && (
                          isDeactivated ? (
                            <button
                              onClick={() => reactivateMutation.mutate(user.username)}
                              disabled={reactivateMutation.isPending}
                              className="text-xs border border-green-500 text-green-600 rounded px-2 py-1 hover:bg-green-50 disabled:opacity-50 transition-colors"
                            >
                              Reactivate
                            </button>
                          ) : confirmDeactivate === user.username ? (
                            <span className="inline-flex gap-1 items-center">
                              <button
                                onClick={() => deactivateMutation.mutate(user.username)}
                                disabled={deactivateMutation.isPending}
                                className="text-xs border border-red-500 text-red-600 rounded px-2 py-1 hover:bg-red-50 disabled:opacity-50 transition-colors"
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => setConfirmDeactivate(null)}
                                className="text-xs border border-gray-300 text-gray-500 rounded px-2 py-1 hover:bg-gray-50 transition-colors"
                              >
                                Cancel
                              </button>
                            </span>
                          ) : (
                            <button
                              onClick={() => setConfirmDeactivate(user.username)}
                              className="text-xs border border-red-300 text-red-500 rounded px-2 py-1 hover:bg-red-50 transition-colors"
                            >
                              Deactivate
                            </button>
                          )
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => toggleNotes(user.username)}
                          className={`text-xs rounded px-2 py-1 border transition-colors ${
                            notesOpen
                              ? "border-amber-400 bg-amber-50 text-amber-700 hover:bg-amber-100"
                              : "border-gray-300 text-gray-500 hover:bg-gray-50"
                          }`}
                          title={notesOpen ? "Hide moderator notes" : "Show moderator notes"}
                        >
                          {notesOpen ? "Hide notes" : "Notes"}
                        </button>
                      </td>
                    </tr>
                    {notesOpen && (
                      <tr key={`${user.id}-notes`}>
                        <td colSpan={10} className="p-0">
                          <ModeratorNotes username={user.username} />
                        </td>
                      </tr>
                    )}
                    </>
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
