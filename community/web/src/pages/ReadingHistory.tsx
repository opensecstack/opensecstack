import { useState, useEffect } from "react";
import { fetchReadingHistory } from "@/api/readingHistory";
import type { HistoryPost } from "@/api/readingHistory";
import PostCard from "@/components/PostCard";
import Spinner from "@/components/Spinner";
import { timeAgo } from "@/lib/format";
import EmptyState, { HistoryEmptyIcon } from "@/components/EmptyState";

const LIMIT = 20;

export default function ReadingHistory() {
  const [posts, setPosts] = useState<HistoryPost[]>([]);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadPage(1, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadPage(targetPage: number, reset = false) {
    setLoading(true);
    try {
      const data = await fetchReadingHistory(targetPage, LIMIT);
      const newPosts = data.posts ?? [];
      setPosts((prev) => (reset ? newPosts : [...prev, ...newPosts]));
      setHasMore(newPosts.length === LIMIT);
    } finally {
      setLoading(false);
    }
  }

  function handleLoadMore() {
    const nextPage = page + 1;
    setPage(nextPage);
    loadPage(nextPage);
  }

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-6">Reading History</h1>
      {loading && posts.length === 0 ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {posts.map((p) => (
            <div key={p.id}>
              <p className="text-xs text-gray-400 dark:text-gray-500 mb-1 pl-1">
                Read {timeAgo(p.read_at)}
              </p>
              <PostCard post={p} />
            </div>
          ))}
          {!loading && posts.length === 0 && (
            <EmptyState
              icon={<HistoryEmptyIcon />}
              title="No reading history"
              description="Posts you read will appear here"
            />
          )}
        </div>
      )}
      {hasMore && (
        <div className="flex justify-center mt-6">
          <button
            onClick={handleLoadMore}
            disabled={loading}
            className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg hover:border-brand hover:text-brand transition-colors disabled:opacity-50"
          >
            {loading ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
      {!hasMore && posts.length > 0 && (
        <p className="text-center text-sm text-gray-400 dark:text-gray-500 mt-6">
          You've reached the end.
        </p>
      )}
    </div>
  );
}
