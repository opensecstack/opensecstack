import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import SEO from "@/components/SEO";
import { fetchLeaderboard, type LeaderboardEntry } from "@/api/leaderboard";

// ---------------------------------------------------------------------------
// Rank badge
// ---------------------------------------------------------------------------
function RankBadge({ rank }: { rank: number }) {
  let cls = "w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold flex-shrink-0 ";
  if (rank === 1) cls += "bg-yellow-400 text-yellow-900";
  else if (rank === 2) cls += "bg-gray-300 text-gray-800";
  else if (rank === 3) cls += "bg-amber-600 text-white";
  else cls += "bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400";
  return <span className={cls}>{rank}</span>;
}

// ---------------------------------------------------------------------------
// Skeleton row
// ---------------------------------------------------------------------------
function SkeletonRow() {
  return (
    <div className="flex items-center gap-4 px-4 py-3 animate-pulse">
      <div className="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-700 flex-shrink-0" />
      <div className="w-10 h-10 rounded-full bg-gray-200 dark:bg-gray-700 flex-shrink-0" />
      <div className="flex-1 space-y-2">
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/3" />
        <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded w-1/4" />
      </div>
      <div className="hidden sm:flex gap-6">
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-10" />
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-10" />
        <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-10" />
      </div>
      <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-14" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Leaderboard row
// ---------------------------------------------------------------------------
function LeaderboardRow({ entry }: { entry: LeaderboardEntry }) {
  const { user, rank, post_count, total_reactions, total_views, score } = entry;
  const initials = (user.display_name || user.username)[0].toUpperCase();

  return (
    <Link
      to={`/users/${user.username}`}
      className="flex items-center gap-4 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors group"
    >
      {/* Rank */}
      <RankBadge rank={rank} />

      {/* Avatar */}
      <div className="w-10 h-10 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold flex-shrink-0 overflow-hidden">
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

      {/* Name */}
      <div className="flex-1 min-w-0">
        <p className="font-semibold text-sm text-gray-900 dark:text-gray-100 truncate group-hover:text-brand transition-colors">
          {user.display_name || user.username}
        </p>
        <p className="text-xs text-gray-400 dark:text-gray-500 truncate">@{user.username}</p>
      </div>

      {/* Stats — hidden on mobile */}
      <div className="hidden sm:flex items-center gap-6 text-sm text-gray-500 dark:text-gray-400 flex-shrink-0">
        <span title="Posts" className="flex flex-col items-center">
          <span className="font-medium text-gray-700 dark:text-gray-300">{post_count}</span>
          <span className="text-xs">posts</span>
        </span>
        <span title="Reactions" className="flex flex-col items-center">
          <span className="font-medium text-gray-700 dark:text-gray-300">{total_reactions}</span>
          <span className="text-xs">reactions</span>
        </span>
        <span title="Views" className="flex flex-col items-center">
          <span className="font-medium text-gray-700 dark:text-gray-300">{total_views}</span>
          <span className="text-xs">views</span>
        </span>
      </div>

      {/* Score — always visible */}
      <div className="flex flex-col items-end flex-shrink-0">
        <span className="text-sm font-bold text-brand">{score.toLocaleString()}</span>
        <span className="text-xs text-gray-400 dark:text-gray-500">score</span>
      </div>
    </Link>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------
export default function Leaderboard() {
  const [searchParams, setSearchParams] = useSearchParams();
  const period = searchParams.get("period") === "month" ? "month" : "week";

  const { data, isLoading, isError } = useQuery({
    queryKey: ["leaderboard", period],
    queryFn: () => fetchLeaderboard(period),
  });

  function setPeriod(p: string) {
    setSearchParams({ period: p }, { replace: true });
  }

  const entries = data?.entries ?? [];

  return (
    <div className="max-w-3xl mx-auto">
      <SEO
        title="Leaderboard"
        description="Top contributors on SIN ranked by reactions, views, and post count."
      />

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Leaderboard</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Top contributors ranked by score (reactions × 3 + views).
        </p>
      </div>

      {/* Period tabs */}
      <div className="flex gap-1 mb-6 bg-gray-100 dark:bg-gray-800 rounded-lg p-1 w-fit">
        {(["week", "month"] as const).map((p) => (
          <button
            key={p}
            onClick={() => setPeriod(p)}
            className={`px-4 py-1.5 text-sm rounded-md font-medium transition-colors ${
              period === p
                ? "bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 shadow-sm"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300"
            }`}
          >
            {p === "week" ? "This Week" : "This Month"}
          </button>
        ))}
      </div>

      {/* Card */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
        {/* Column header — hidden on mobile */}
        {!isLoading && entries.length > 0 && (
          <div className="hidden sm:flex items-center gap-4 px-4 py-2 border-b border-gray-100 dark:border-gray-800 text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-wide">
            <span className="w-8 flex-shrink-0">#</span>
            <span className="w-10 flex-shrink-0" />
            <span className="flex-1">Author</span>
            <span className="flex gap-6 mr-0">
              <span className="w-10 text-center">Posts</span>
              <span className="w-16 text-center">Reactions</span>
              <span className="w-10 text-center">Views</span>
            </span>
            <span className="w-14 text-right">Score</span>
          </div>
        )}

        {/* Loading skeleton */}
        {isLoading && (
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {Array.from({ length: 5 }).map((_, i) => (
              <SkeletonRow key={i} />
            ))}
          </div>
        )}

        {/* Error */}
        {isError && (
          <p className="text-center text-red-500 py-12 text-sm">
            Failed to load leaderboard. Please try again.
          </p>
        )}

        {/* Empty state */}
        {!isLoading && !isError && entries.length === 0 && (
          <p className="text-center text-gray-400 dark:text-gray-500 py-16 text-sm">
            No activity this period.
          </p>
        )}

        {/* Rows */}
        {!isLoading && entries.length > 0 && (
          <div className="divide-y divide-gray-100 dark:divide-gray-800">
            {entries.map((entry) => (
              <LeaderboardRow key={entry.user.id} entry={entry} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
