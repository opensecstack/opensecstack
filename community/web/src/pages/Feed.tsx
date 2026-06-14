import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import SEO from "@/components/SEO";
import { listFeed } from "@/api/posts";
import { listFollowingTagsFeed } from "@/api/tagFollows";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/state/auth";
import type { Post, PostListResponse } from "@/api/posts";
import PostCard from "@/components/PostCard";
import Sidebar from "@/components/Sidebar";
import Spinner from "@/components/Spinner";
import SortTabs from "@/components/SortTabs";
import ScrollSentinel from "@/components/ScrollSentinel";
import { useInfiniteScroll } from "@/hooks/useInfiniteScroll";
import EmptyState, { FeedEmptyIcon, SearchEmptyIcon } from "@/components/EmptyState";

const LIMIT = 20;

async function fetchFeedPage(
  page: number,
  sort: string,
  followingTags: boolean,
  q: string | null
): Promise<Post[]> {
  const offset = (page - 1) * LIMIT;
  let data: PostListResponse;
  if (q) {
    const res = await apiClient.get<PostListResponse>("/api/v1/search", {
      params: { q, limit: LIMIT, offset },
    });
    data = res.data;
  } else if (followingTags) {
    data = (await listFollowingTagsFeed(LIMIT, offset)) as PostListResponse;
  } else {
    data = await listFeed(sort, LIMIT, offset);
  }
  return data.posts ?? [];
}

export default function Feed() {
  const [params] = useSearchParams();
  const q = params.get("q");
  const [sort, setSort] = useState("latest");
  const [followingTags, setFollowingTags] = useState(false);
  const { token } = useAuthStore();

  const { data, hasNextPage, isFetchingNextPage, status, ref } =
    useInfiniteScroll<Post>({
      queryKey: ["feed", sort, followingTags, q],
      fetchFn: (page) => fetchFeedPage(page, sort, followingTags, q),
    });

  const posts = data?.pages.flat() ?? [];
  const isInitialLoading = status === "pending";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[1fr_300px] gap-6">
      <SEO
        title="Feed"
        description="Discover security knowledge, research, and insights from the SIN community."
        rssHref="/api/v1/feed.rss"
        rssTitle="SIN Feed"
      />
      <div>
        {q && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            Results for <strong>"{q}"</strong>
          </p>
        )}
        {!q && (
          <div className="flex items-center gap-3 mb-4">
            <SortTabs
              value={followingTags ? "" : sort}
              onChange={(v) => {
                setFollowingTags(false);
                setSort(v);
              }}
            />
            {!!token && (
              <button
                onClick={() => setFollowingTags((f) => !f)}
                className={`px-4 py-1.5 text-sm rounded-lg border transition-colors whitespace-nowrap ${
                  followingTags
                    ? "bg-brand text-white border-brand"
                    : "border-brand text-brand hover:bg-brand hover:text-white dark:hover:bg-brand"
                }`}
              >
                Following Tags
              </button>
            )}
          </div>
        )}
        {isInitialLoading ? (
          <Spinner />
        ) : (
          <div className="space-y-4">
            {posts.map((p) => (
              <PostCard key={p.id} post={p} />
            ))}
            {!isInitialLoading && posts.length === 0 && (
              q ? (
                <EmptyState
                  icon={<SearchEmptyIcon />}
                  title={`No results for "${q}"`}
                  description="Try different keywords or browse by tag"
                />
              ) : followingTags ? (
                <EmptyState
                  icon={<FeedEmptyIcon />}
                  title="No posts from followed tags yet"
                  description="Follow more tags to fill your feed"
                />
              ) : (
                <EmptyState
                  icon={<FeedEmptyIcon />}
                  title="Nothing here yet"
                  description="Be the first to write a post for the community"
                  action={{ label: "Write a post", href: "/new" }}
                />
              )
            )}
          </div>
        )}
        <ScrollSentinel
          ref={ref}
          isFetchingNextPage={isFetchingNextPage}
          hasNextPage={!!hasNextPage}
        />
        {!hasNextPage && posts.length > 0 && !isFetchingNextPage && (
          <p className="text-center text-sm text-gray-400 dark:text-gray-500 mt-2 pb-6">
            You've reached the end.
          </p>
        )}
      </div>
      <Sidebar />
    </div>
  );
}
