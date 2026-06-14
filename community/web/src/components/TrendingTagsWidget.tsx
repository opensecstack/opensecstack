import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchTrendingTags } from "@/api/tags";

export default function TrendingTagsWidget() {
  const { data } = useQuery({
    queryKey: ["trending-tags"],
    queryFn: fetchTrendingTags,
    staleTime: 5 * 60 * 1000,
  });

  const tags = data?.tags ?? [];

  if (tags.length === 0) return null;

  return (
    <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
      <h3 className="font-semibold text-gray-800 dark:text-gray-200 mb-3 flex items-center gap-1.5">
        <span>🔥</span>
        Trending this week
      </h3>
      <ul className="space-y-2">
        {tags.map((tag) => (
          <li key={tag.id} className="flex items-center justify-between gap-2">
            <Link
              to={`/tags/${tag.slug}`}
              className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 hover:text-brand dark:hover:text-brand transition-colors min-w-0"
            >
              <span
                className="w-2.5 h-2.5 rounded-full flex-shrink-0"
                style={{ backgroundColor: tag.color || "#6366f1" }}
              />
              <span className="truncate">{tag.name}</span>
            </Link>
            <span className="text-xs text-gray-400 dark:text-gray-500 whitespace-nowrap flex-shrink-0">
              {tag.post_count} {tag.post_count === 1 ? "post" : "posts"}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
