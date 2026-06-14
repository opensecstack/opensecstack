import { useQuery } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import { getSpace, type Channel } from "@/api/spaces";
import { getPost } from "@/api/posts";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";
import PostComments from "@/components/post/PostComments";
import TagBadge from "@/components/TagBadge";
import { timeAgo } from "@/lib/format";
import { Hash, Megaphone, Lock, ChevronLeft } from "lucide-react";

export default function SpacePostDetail() {
  const { slug, channelSlug, postSlug } = useParams<{
    slug: string;
    channelSlug: string;
    postSlug: string;
  }>();
  const { token } = useAuthStore();

  const { data: spaceData, isLoading: spaceLoading } = useQuery({
    queryKey: ["space", slug],
    queryFn: () => getSpace(slug!),
  });

  const { data: post, isLoading: postLoading } = useQuery({
    queryKey: ["post", postSlug],
    queryFn: () => getPost(postSlug!),
    enabled: !!postSlug,
  });

  if (spaceLoading || postLoading) return <Spinner />;
  if (!spaceData || !post) return (
    <div className="text-center py-16 text-gray-400 dark:text-gray-500">
      <p>Post not found.</p>
      <Link to={`/spaces/${slug}`} className="text-brand hover:underline text-sm mt-2 inline-block">
        ← Back to space
      </Link>
    </div>
  );

  const { space, channels } = spaceData;
  const isMember = space.is_member;
  const isOwner = space.viewer_role === "owner";
  const currentChannel = channels.find((ch: Channel) => ch.slug === channelSlug);

  return (
    <div className="flex gap-0 -mx-4 -my-6 min-h-[calc(100vh-3.5rem)]">
      {/* Channels sidebar */}
      <aside className="w-56 shrink-0 bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800 flex flex-col">
        <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-xl">{space.icon_emoji}</span>
            <div className="min-w-0">
              <h2 className="font-semibold text-sm text-gray-900 dark:text-gray-100 truncate">{space.name}</h2>
              <p className="text-xs text-gray-500 dark:text-gray-400">{space.member_count} members</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-2 overflow-y-auto">
          <div className="px-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">Channels</span>
          </div>
          {channels.map((ch: Channel) => (
            <Link
              key={ch.id}
              to={`/spaces/${slug}?channel=${ch.slug}`}
              className={`w-full flex items-center gap-1.5 px-2 py-1.5 rounded text-sm transition-colors text-left ${
                ch.slug === channelSlug
                  ? "bg-gray-200 dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-900 hover:text-gray-900 dark:hover:text-gray-200"
              }`}
            >
              {ch.type === "announcement"
                ? <Megaphone className="w-3.5 h-3.5 shrink-0" />
                : <Hash className="w-3.5 h-3.5 shrink-0" />
              }
              <span className="truncate">{ch.name}</span>
            </Link>
          ))}
        </nav>

        {isOwner && (
          <div className="p-2 border-t border-gray-200 dark:border-gray-800">
            <Link
              to={`/spaces/${slug}/settings`}
              className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-gray-500 dark:text-gray-400 hover:text-brand rounded hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors"
            >
              Settings
            </Link>
          </div>
        )}
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Channel header */}
        <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-800 flex items-center gap-2 bg-white dark:bg-gray-900 sticky top-0 z-10">
          <Link
            to={`/spaces/${slug}?channel=${channelSlug}`}
            className="flex items-center gap-1 text-gray-400 hover:text-brand text-sm transition-colors mr-1"
          >
            <ChevronLeft className="w-4 h-4" />
          </Link>
          {currentChannel?.type === "announcement"
            ? <Megaphone className="w-4 h-4 text-gray-400" />
            : <Hash className="w-4 h-4 text-gray-400" />
          }
          <span className="font-medium text-sm text-gray-900 dark:text-gray-100">
            {currentChannel?.name ?? channelSlug}
          </span>
          {space.is_private && <Lock className="w-3.5 h-3.5 text-gray-400 ml-1" />}
        </div>

        {/* Post content */}
        <div className="flex-1 p-6 max-w-3xl w-full">
          {/* Announcement badge */}
          {currentChannel?.type === "announcement" && (
            <div className="flex items-center gap-1.5 mb-3">
              <Megaphone className="w-4 h-4 text-amber-500" />
              <span className="text-xs font-semibold text-amber-600 dark:text-amber-400 uppercase tracking-wide">Announcement</span>
            </div>
          )}

          {/* Post header */}
          <div className="mb-6">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100 mb-3">{post.title}</h1>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-8 h-8 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-sm shrink-0">
                {post.author_display_name?.[0] ?? post.author_username[0]}
              </div>
              <div>
                <Link to={`/users/${post.author_username}`} className="text-sm font-medium hover:text-brand">
                  {post.author_display_name || post.author_username}
                </Link>
                {post.author_platform_badge && (
                  <span className="ml-2 text-xs bg-indigo-50 dark:bg-indigo-900/20 text-brand px-1.5 py-0.5 rounded">
                    {post.author_platform_badge}
                  </span>
                )}
                <p className="text-xs text-gray-400 dark:text-gray-500">
                  {timeAgo(post.published_at ?? post.created_at)}
                  {post.edited_at && <span className="ml-1">· Edited</span>}
                </p>
              </div>
            </div>
            {post.tags.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mb-4">
                {post.tags.map((t) => <TagBadge key={t} name={t} />)}
              </div>
            )}
          </div>

          {/* Post body */}
          {post.body && (
            <div className="prose prose-sm dark:prose-invert max-w-none mb-8 text-gray-800 dark:text-gray-200 whitespace-pre-wrap">
              {post.body}
            </div>
          )}

          {/* Divider */}
          <div className="border-t border-gray-200 dark:border-gray-800 pt-6">
            {isMember || !space.is_private ? (
              <PostComments postId={post.id} locked={post.locked ?? false} />
            ) : (
              <div className="text-center py-8 text-gray-400 dark:text-gray-500">
                <p className="text-sm">
                  {token ? "Join this space to comment." : (
                    <><Link to="/login" className="text-brand hover:underline">Log in</Link> and join this space to comment.</>
                  )}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
