import { useState, useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import SEO from "@/components/SEO";
import { fetchUsers, type DirectoryUser } from "@/api/users";
import { followUser, unfollowUser, getFollowStatus } from "@/api/follows";
import { useAuthStore } from "@/state/auth";

// ---------------------------------------------------------------------------
// Skeleton card
// ---------------------------------------------------------------------------
function SkeletonCard() {
  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4 animate-pulse">
      <div className="flex items-center gap-3 mb-3">
        <div className="w-12 h-12 rounded-full bg-gray-200 dark:bg-gray-700 flex-shrink-0" />
        <div className="flex-1 space-y-2">
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
          <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/2" />
        </div>
      </div>
      <div className="space-y-1.5">
        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-full" />
        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-5/6" />
      </div>
      <div className="mt-3 h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/4" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Inline follow button (avoids fetching follow status for every card until
// the user is authenticated — keeps unauthenticated browsing cheap)
// ---------------------------------------------------------------------------
interface InlineFollowButtonProps {
  username: string;
}

function InlineFollowButton({ username }: InlineFollowButtonProps) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["follow-status", username],
    queryFn: () => getFollowStatus(username),
    enabled: !!token && me !== username,
  });

  if (!token || me === username) return null;

  async function toggle() {
    if (data?.following) {
      await unfollowUser(username);
    } else {
      await followUser(username);
    }
    qc.invalidateQueries({ queryKey: ["follow-status", username] });
  }

  return (
    <button
      onClick={(e) => {
        e.preventDefault();
        toggle();
      }}
      disabled={isLoading}
      className={`flex-shrink-0 px-3 py-1 text-xs rounded-lg border transition-colors disabled:opacity-50 ${
        data?.following
          ? "border-green-500 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-950"
          : "border-brand text-brand hover:bg-brand hover:text-white"
      }`}
    >
      {data?.following ? "Following" : "Follow"}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Single user card
// ---------------------------------------------------------------------------
interface UserCardProps {
  user: DirectoryUser;
}

function UserCard({ user }: UserCardProps) {
  const initials = (user.display_name || user.username)[0].toUpperCase();

  return (
    <Link
      to={`/users/${user.username}`}
      className="group bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4 flex flex-col gap-3 hover:border-brand dark:hover:border-brand transition-colors"
    >
      {/* Header row: avatar + name + follow */}
      <div className="flex items-start gap-3">
        <div className="w-12 h-12 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-lg flex-shrink-0 overflow-hidden">
          {user.avatar_url ? (
            <img
              src={user.avatar_url}
              alt={user.display_name || user.username}
              className="w-full h-full object-cover"
            />
          ) : (
            initials
          )}
        </div>

        <div className="flex-1 min-w-0">
          <p className="font-bold text-sm text-gray-900 dark:text-gray-100 truncate group-hover:text-brand transition-colors">
            {user.display_name || user.username}
          </p>
          <p className="text-xs text-gray-400 dark:text-gray-500 truncate">@{user.username}</p>
        </div>

        <InlineFollowButton username={user.username} />
      </div>

      {/* Bio */}
      {user.bio ? (
        <p className="text-xs text-gray-600 dark:text-gray-400 line-clamp-2 leading-relaxed">
          {user.bio}
        </p>
      ) : (
        <p className="text-xs text-gray-300 dark:text-gray-600 italic">No bio yet.</p>
      )}

      {/* Post count */}
      <p className="text-xs text-gray-400 dark:text-gray-500 mt-auto">
        {user.post_count} {user.post_count === 1 ? "post" : "posts"}
      </p>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
const PAGE_SIZE = 20;

export default function UserDirectory() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [inputValue, setInputValue] = useState(searchParams.get("q") ?? "");
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const q = searchParams.get("q") ?? "";
  const page = parseInt(searchParams.get("page") ?? "1", 10);

  // Sync input → URL param (debounced 300 ms, reset page to 1 on new search)
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (inputValue) {
          next.set("q", inputValue);
        } else {
          next.delete("q");
        }
        next.set("page", "1");
        return next;
      }, { replace: true });
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [inputValue, setSearchParams]);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["user-directory", q, page],
    queryFn: () => fetchUsers(q, page),
    placeholderData: (prev) => prev,
  });

  const users = data?.users ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  function goToPage(p: number) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("page", String(p));
      return next;
    }, { replace: true });
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  return (
    <div className="max-w-6xl mx-auto">
      <SEO
        title="Community Members"
        description="Browse all active members of the SIN community."
      />

      {/* Page header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Community Members</h1>
        {!isLoading && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            {total} {total === 1 ? "member" : "members"}{q ? ` matching "${q}"` : ""}
          </p>
        )}
      </div>

      {/* Search */}
      <div className="mb-6">
        <input
          type="search"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder="Search by username or display name…"
          className="w-full sm:max-w-sm px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-brand focus:border-transparent"
        />
      </div>

      {/* Error state */}
      {isError && (
        <p className="text-center text-red-500 py-12">Failed to load members. Please try again.</p>
      )}

      {/* Loading skeleton */}
      {isLoading && (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && users.length === 0 && (
        <div className="text-center py-20">
          <p className="text-gray-400 dark:text-gray-500 text-lg">No members found.</p>
          {q && (
            <button
              onClick={() => {
                setInputValue("");
                setSearchParams({}, { replace: true });
              }}
              className="mt-3 text-sm text-brand hover:underline"
            >
              Clear search
            </button>
          )}
        </div>
      )}

      {/* Grid */}
      {!isLoading && users.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
          {users.map((user) => (
            <UserCard key={user.id} user={user} />
          ))}
        </div>
      )}

      {/* Pagination */}
      {!isLoading && totalPages > 1 && (
        <div className="flex items-center justify-center gap-3 mt-8">
          <button
            onClick={() => goToPage(page - 1)}
            disabled={page <= 1}
            className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:border-brand hover:text-brand transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            ← Prev
          </button>

          <span className="text-sm text-gray-500 dark:text-gray-400">
            Page {page} of {totalPages}
          </span>

          <button
            onClick={() => goToPage(page + 1)}
            disabled={page >= totalPages}
            className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:border-brand hover:text-brand transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
