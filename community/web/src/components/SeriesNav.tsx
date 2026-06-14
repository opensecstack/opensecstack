import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { getPostSeries } from "@/api/series";
import { ChevronLeft, ChevronRight, BookOpen } from "lucide-react";

interface Props {
  postId: string;
}

export default function SeriesNav({ postId }: Props) {
  const { data } = useQuery({
    queryKey: ["post-series", postId],
    queryFn: () => getPostSeries(postId),
  });

  if (!data?.series) return null;

  const { series, posts, current_position } = data;
  const total = posts.length;

  const currentIndex = posts.findIndex((p) => p.position === current_position);
  const prev = currentIndex > 0 ? posts[currentIndex - 1] : null;
  const next = currentIndex >= 0 && currentIndex < posts.length - 1 ? posts[currentIndex + 1] : null;

  const hasPrevNext = prev !== null || next !== null;

  return (
    <div className="mt-6 bg-indigo-50 border border-indigo-100 rounded-lg p-4">
      {/* Header row */}
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2 min-w-0">
          <BookOpen className="w-4 h-4 text-indigo-500 flex-shrink-0" />
          <span className="text-sm text-indigo-700">
            Part {current_position} of {total} in:{" "}
            <Link
              to={`/series/${series.slug}`}
              className="font-semibold text-indigo-800 hover:underline"
            >
              {series.title}
            </Link>
          </span>
        </div>
        <Link
          to={`/series/${series.slug}`}
          className="flex-shrink-0 text-xs text-indigo-600 hover:text-indigo-800 hover:underline whitespace-nowrap"
        >
          View full series →
        </Link>
      </div>

      {/* Prev / Next navigation */}
      {hasPrevNext && (
        <div
          className={`grid gap-px rounded-md overflow-hidden border border-indigo-100 ${
            prev && next ? "grid-cols-2" : "grid-cols-1"
          }`}
        >
          {prev && (
            <Link
              to={`/posts/${prev.slug}`}
              className="flex items-center gap-2 bg-white hover:bg-indigo-50 px-4 py-3 transition-colors group"
            >
              <ChevronLeft className="w-4 h-4 text-indigo-400 group-hover:text-indigo-600 flex-shrink-0" />
              <div className="min-w-0">
                <p className="text-xs text-indigo-400 group-hover:text-indigo-600">Previous</p>
                <p className="text-sm text-gray-700 group-hover:text-indigo-800 truncate font-medium">
                  {prev.title}
                </p>
              </div>
            </Link>
          )}
          {next && (
            <Link
              to={`/posts/${next.slug}`}
              className="flex items-center justify-end gap-2 bg-white hover:bg-indigo-50 px-4 py-3 transition-colors group text-right"
            >
              <div className="min-w-0">
                <p className="text-xs text-indigo-400 group-hover:text-indigo-600">Next</p>
                <p className="text-sm text-gray-700 group-hover:text-indigo-800 truncate font-medium">
                  {next.title}
                </p>
              </div>
              <ChevronRight className="w-4 h-4 text-indigo-400 group-hover:text-indigo-600 flex-shrink-0" />
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
