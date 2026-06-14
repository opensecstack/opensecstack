import { Link, Navigate } from "react-router-dom";
import { getFollowingFeed } from "@/api/posts";
import type { Post } from "@/api/posts";
import PostCard from "@/components/PostCard";
import Sidebar from "@/components/Sidebar";
import Spinner from "@/components/Spinner";
import ScrollSentinel from "@/components/ScrollSentinel";
import { useAuthStore } from "@/state/auth";
import { useInfiniteScroll } from "@/hooks/useInfiniteScroll";

const LIMIT = 20;

export default function FollowingFeed() {
  const { token } = useAuthStore();

  if (!token) return <Navigate to="/login" replace />;

  const { data, hasNextPage, isFetchingNextPage, status, ref } =
    useInfiniteScroll<Post>({
      queryKey: ["feed", "following"],
      fetchFn: (page) => {
        const offset = (page - 1) * LIMIT;
        return getFollowingFeed(LIMIT, offset).then((d) => d.posts ?? []);
      },
    });

  const posts = data?.pages.flat() ?? [];
  const isInitialLoading = status === "pending";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_300px] gap-6">
      <div>
        <h1 className="text-xl font-bold text-gray-800 mb-4">Following</h1>
        {isInitialLoading ? (
          <Spinner />
        ) : (
          <div className="space-y-4">
            {posts.map((p) => (
              <PostCard key={p.id} post={p} />
            ))}
            {posts.length === 0 && (
              <p className="text-center text-gray-400 py-12">
                No posts yet. Follow some authors to see their posts here.{" "}
                <Link to="/" className="text-brand hover:underline">
                  Browse posts
                </Link>
              </p>
            )}
          </div>
        )}
        <ScrollSentinel
          ref={ref}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={!!hasNextPage}
        />
        {!hasNextPage && posts.length > 0 && !isFetchingNextPage && (
          <p className="text-center text-sm text-gray-400 mt-2 pb-6">
            You've reached the end.
          </p>
        )}
      </div>
      <Sidebar />
    </div>
  );
}
