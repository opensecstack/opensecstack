import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { listPostsByTag, getTag } from "@/api/tags";
import { followTag, unfollowTag, getTagFollowStatus } from "@/api/tagFollows";
import { useAuthStore } from "@/state/auth";
import type { Post } from "@/api/posts";
import PostCard from "@/components/PostCard";
import Spinner from "@/components/Spinner";
import SortTabs from "@/components/SortTabs";
import ScrollSentinel from "@/components/ScrollSentinel";
import { useInfiniteScroll } from "@/hooks/useInfiniteScroll";

const LIMIT = 20;

export default function TagFeed() {
  const { slug } = useParams<{ slug: string }>();
  const [sort, setSort] = useState("latest");
  const { token } = useAuthStore();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const { data, hasNextPage, isFetchingNextPage, status, ref } =
    useInfiniteScroll<Post>({
      queryKey: ["tag-feed", slug, sort],
      fetchFn: (page) => {
        const offset = (page - 1) * LIMIT;
        return listPostsByTag(slug!, sort, LIMIT, offset).then(
          (d) => d.posts ?? []
        );
      },
      enabled: !!slug,
    });

  const posts = data?.pages.flat() ?? [];
  const isInitialLoading = status === "pending";

  const { data: tagData } = useQuery({
    queryKey: ["tag", slug],
    queryFn: () => getTag(slug!),
    enabled: !!slug,
  });

  const { data: followStatus, refetch: refetchFollow } = useQuery({
    queryKey: ["tag-follow-status", slug],
    queryFn: () => getTagFollowStatus(slug!),
    enabled: !!token && !!slug,
  });

  const following = followStatus?.following ?? false;

  async function handleFollowToggle() {
    if (!token) {
      navigate("/login");
      return;
    }
    if (following) {
      await unfollowTag(slug!);
    } else {
      await followTag(slug!);
    }
    refetchFollow();
    qc.invalidateQueries({ queryKey: ["tag-follow-status", slug] });
  }

  return (
    <div className="max-w-3xl mx-auto">
      {/* Tag header */}
      <div className="mb-8 p-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              #{tagData?.name ?? slug}
            </h1>
            {tagData?.description && (
              <p className="mt-2 text-gray-600 dark:text-gray-400">{tagData.description}</p>
            )}
            <div className="mt-3 flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
              {tagData != null && <span>{tagData.post_count} posts</span>}
              {tagData != null && <span>{tagData.follower_count} followers</span>}
            </div>
          </div>
          <button
            onClick={handleFollowToggle}
            className="shrink-0 ml-4 px-4 py-1.5 text-sm rounded-lg border border-brand text-brand hover:bg-brand hover:text-white transition-colors"
          >
            {following ? "Unfollow" : "Follow"}
          </button>
        </div>
      </div>
      <SortTabs value={sort} onChange={setSort} />
      {isInitialLoading ? (
        <Spinner />
      ) : (
        <div className="space-y-4">
          {posts.map((p) => (
            <PostCard key={p.id} post={p} />
          ))}
          {posts.length === 0 && (
            <p className="text-center text-gray-400 py-12">
              No posts with this tag yet.
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
  );
}
