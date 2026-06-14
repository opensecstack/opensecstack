import { useState, useEffect } from "react";
import { listMyBookmarks } from "@/api/bookmarks";
import type { Post } from "@/api/posts";
import PostCard from "@/components/PostCard";
import Spinner from "@/components/Spinner";
import EmptyState, { BookmarkEmptyIcon } from "@/components/EmptyState";

const LIMIT = 20;

export default function Bookmarks() {
  const [posts, setPosts] = useState<Post[]>([]);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadPosts(0, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function loadPosts(currentOffset: number, reset = false) {
    setLoading(true);
    try {
      const data = await listMyBookmarks(LIMIT, currentOffset);
      const newPosts = data.posts ?? [];
      setPosts((prev) => (reset ? newPosts : [...prev, ...newPosts]));
      setHasMore(newPosts.length === LIMIT);
    } finally {
      setLoading(false);
    }
  }

  function handleLoadMore() {
    const nextOffset = offset + LIMIT;
    setOffset(nextOffset);
    loadPosts(nextOffset);
  }

  return (
    <div className="max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Your Bookmarks</h1>
      {loading && posts.length === 0 ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {posts.map((p) => (
            <PostCard key={p.id} post={p} />
          ))}
          {!loading && posts.length === 0 && (
            <EmptyState
              icon={<BookmarkEmptyIcon />}
              title="No bookmarks yet"
              description="Save posts to read later by clicking the bookmark icon"
            />
          )}
        </div>
      )}
      {hasMore && (
        <div className="flex justify-center mt-6">
          <button
            onClick={handleLoadMore}
            disabled={loading}
            className="px-4 py-2 text-sm border border-gray-300 rounded-lg hover:border-brand hover:text-brand transition-colors disabled:opacity-50"
          >
            {loading ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
      {!hasMore && posts.length > 0 && (
        <p className="text-center text-sm text-gray-400 mt-6">You've reached the end.</p>
      )}
    </div>
  );
}
