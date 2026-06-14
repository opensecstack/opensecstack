import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchSuggestedUsers } from "@/api/users";
import { followUser, unfollowUser, getFollowStatus } from "@/api/follows";
import { useAuthStore } from "@/state/auth";

function UserInitials({ displayName }: { displayName: string }) {
  const initials = displayName
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join("");
  return (
    <span className="flex items-center justify-center w-9 h-9 rounded-full bg-indigo-100 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 text-sm font-semibold flex-shrink-0">
      {initials || "?"}
    </span>
  );
}

function FollowToggle({ username }: { username: string }) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);

  const { data } = useQuery({
    queryKey: ["follow-status", username],
    queryFn: () => getFollowStatus(username),
    enabled: !!token && me !== username,
  });

  if (!token || me === username) return null;

  async function toggle() {
    setBusy(true);
    try {
      if (data?.following) {
        await unfollowUser(username);
      } else {
        await followUser(username);
      }
      qc.invalidateQueries({ queryKey: ["follow-status", username] });
      qc.invalidateQueries({ queryKey: ["suggested-users"] });
    } finally {
      setBusy(false);
    }
  }

  return (
    <button
      onClick={toggle}
      disabled={busy}
      className="text-xs px-2.5 py-1 rounded-md border border-brand text-brand hover:bg-brand hover:text-white transition-colors disabled:opacity-50 flex-shrink-0"
    >
      {data?.following ? "Unfollow" : "Follow"}
    </button>
  );
}

function SkeletonRow() {
  return (
    <div className="flex items-center gap-2 animate-pulse">
      <div className="w-9 h-9 rounded-full bg-gray-200 dark:bg-gray-700 flex-shrink-0" />
      <div className="flex-1 space-y-1.5">
        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-24" />
        <div className="h-2.5 bg-gray-200 dark:bg-gray-700 rounded w-16" />
      </div>
    </div>
  );
}

export default function SuggestedUsersWidget() {
  const { data, isLoading } = useQuery({
    queryKey: ["suggested-users"],
    queryFn: fetchSuggestedUsers,
    staleTime: 5 * 60 * 1000,
  });

  const users = data?.users ?? [];

  if (!isLoading && users.length === 0) return null;

  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <h3 className="font-semibold text-gray-800 dark:text-gray-200 mb-3">Who to Follow</h3>
      <ul className="space-y-3">
        {isLoading
          ? Array.from({ length: 3 }).map((_, i) => <li key={i}><SkeletonRow /></li>)
          : users.map((user) => (
              <li key={user.username} className="flex items-center gap-2">
                <Link to={`/u/${user.username}`} className="flex-shrink-0">
                  {user.avatar_url ? (
                    <img
                      src={user.avatar_url}
                      alt={user.display_name}
                      className="w-9 h-9 rounded-full object-cover"
                    />
                  ) : (
                    <UserInitials displayName={user.display_name || user.username} />
                  )}
                </Link>
                <div className="flex-1 min-w-0">
                  <Link
                    to={`/u/${user.username}`}
                    className="block text-sm font-medium text-gray-800 dark:text-gray-200 hover:text-brand dark:hover:text-brand transition-colors truncate"
                  >
                    {user.display_name || user.username}
                  </Link>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    @{user.username} &middot; {user.follower_count.toLocaleString()} follower{user.follower_count !== 1 ? "s" : ""}
                  </p>
                </div>
                <FollowToggle username={user.username} />
              </li>
            ))}
      </ul>
    </div>
  );
}
