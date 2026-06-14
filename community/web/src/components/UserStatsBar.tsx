interface UserStats {
  post_count: number;
  reaction_count: number;
  view_count: number;
}

interface UserStatsBarProps {
  stats: UserStats;
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1).replace(/\.0$/, "")}K`;
  return String(n);
}

export default function UserStatsBar({ stats }: UserStatsBarProps) {
  return (
    <div className="flex items-center gap-4 mt-3 text-sm text-gray-500 dark:text-gray-400">
      <span title="Published posts">
        📝 {formatCount(stats.post_count)} {stats.post_count === 1 ? "Post" : "Posts"}
      </span>
      <span title="Reactions received">
        ❤️ {formatCount(stats.reaction_count)} {stats.reaction_count === 1 ? "Reaction" : "Reactions"}
      </span>
      <span title="Total views">
        👁 {formatCount(stats.view_count)} {stats.view_count === 1 ? "View" : "Views"}
      </span>
    </div>
  );
}
