import { useQuery, useMutation } from "@tanstack/react-query";
import { useParams, Link, useNavigate } from "react-router-dom";
import SEO from "@/components/SEO";
import { getPost } from "@/api/posts";
import { fetchPostReactions, addReaction, removeReaction } from "@/api/reactions";
import type { PostReactionsResponse } from "@/api/reactions";
import { recordView } from "@/api/views";
import { recordRead } from "@/api/readingHistory";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";
import { readingTime } from "@/lib/readingTime";
import { renderBody } from "@/lib/renderBody";
import TagBadge from "@/components/TagBadge";
import Spinner from "@/components/Spinner";
import BookmarkButton from "@/components/BookmarkButton";
import ShareButton from "@/components/ShareButton";
import ShareButtons from "@/components/ShareButtons";
import ReactionBar from "@/components/ReactionBar";
import { MessageCircle, Lock, Unlock, Pin, Pencil } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { lockPost, unlockPost } from "@/api/posts";
import { pinPost, unpinPost } from "@/api/pin";
import ContextNote from "@/components/ContextNote";
import SeriesNav from "@/components/SeriesNav";
import RelatedPosts from "@/components/RelatedPosts";
import { subscribePost, unsubscribePost, getPostSubscriptionStatus } from "@/api/subscriptions";
import TableOfContents from "@/components/TableOfContents";
import { useToc } from "@/hooks/useToc";
import { ReadingProgress } from "@/components/ReadingProgress";
import PostComments from "@/components/post/PostComments";

export default function PostDetail() {
  const { slug } = useParams<{ slug: string }>();
  const { token } = useAuthStore();
  const role = useAuthStore((s) => s.role);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [lockedState, setLockedState] = useState(false);
  const [pinnedState, setPinnedState] = useState(false);
  const [subscribed, setSubscribed] = useState(false);
  const [showSensitive, setShowSensitive] = useState(false);

  const { data: post, isLoading } = useQuery({
    queryKey: ["post", slug],
    queryFn: () => getPost(slug!),
  });

  // Per-kind reaction counts + user's own reactions
  const reactionsQueryKey = ["post-reactions", post?.id] as const;
  const { data: reactionsData } = useQuery({
    queryKey: reactionsQueryKey,
    queryFn: () => fetchPostReactions(post!.id),
    enabled: !!post?.id,
  });

  const reactionCounts: Record<string, number> = reactionsData?.reactions ?? {};
  const userReactions: string[] = reactionsData?.user_reactions ?? [];

  const reactMutation = useMutation({
    mutationFn: ({ kind, remove }: { kind: string; remove: boolean }) =>
      remove
        ? removeReaction(post!.id, kind)
        : addReaction(post!.id, kind),
    onMutate: async ({ kind, remove }) => {
      await qc.cancelQueries({ queryKey: reactionsQueryKey });
      const prev = qc.getQueryData<PostReactionsResponse>(reactionsQueryKey);
      qc.setQueryData<PostReactionsResponse>(reactionsQueryKey, (old) => {
        const base: PostReactionsResponse = old ?? { reactions: {}, user_reactions: [] };
        const newCounts = { ...base.reactions };
        if (remove) {
          newCounts[kind] = Math.max(0, (newCounts[kind] ?? 1) - 1);
          if (newCounts[kind] === 0) delete newCounts[kind];
        } else {
          newCounts[kind] = (newCounts[kind] ?? 0) + 1;
        }
        return {
          reactions: newCounts,
          user_reactions: remove
            ? base.user_reactions.filter((k) => k !== kind)
            : [...base.user_reactions, kind],
        };
      });
      return { prev };
    },
    onError: (_err, _vars, context) => {
      if (context?.prev !== undefined) {
        qc.setQueryData(reactionsQueryKey, context.prev);
      }
    },
    onSettled: () => {
      qc.invalidateQueries({ queryKey: reactionsQueryKey });
    },
  });

  function handleReact(kind: string) {
    if (!token) { navigate("/login"); return; }
    reactMutation.mutate({ kind, remove: false });
  }

  function handleUnreact(kind: string) {
    if (!token) { navigate("/login"); return; }
    reactMutation.mutate({ kind, remove: true });
  }

  // Table of contents
  const contentRef = useRef<HTMLDivElement>(null);
  const { entries: tocEntries, activeId: tocActiveId } = useToc(contentRef);

  // Reading progress
  const [readProgress, setReadProgress] = useState(0);
  const progressTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!post?.id) return;

    function handleScroll() {
      const scrolled = window.scrollY;
      const total = document.documentElement.scrollHeight - window.innerHeight;
      const pct = total > 0 ? Math.round((scrolled / total) * 100) : 0;
      setReadProgress(pct);

      if (progressTimerRef.current) clearTimeout(progressTimerRef.current);
      const postId = post?.id;
      progressTimerRef.current = setTimeout(() => {
        if (!postId) return;
        if (pct >= 95) {
          localStorage.removeItem(`sin:read:${postId}`);
        } else if (pct > 5) {
          localStorage.setItem(`sin:read:${postId}`, String(pct));
        }
      }, 1000);
    }

    window.addEventListener("scroll", handleScroll, { passive: true });
    return () => {
      window.removeEventListener("scroll", handleScroll);
      if (progressTimerRef.current) clearTimeout(progressTimerRef.current);
    };
  }, [post?.id]);

  // Resume reading toast
  const [showResume, setShowResume] = useState(false);
  const savedPctRef = useRef(0);
  useEffect(() => {
    if (!post?.id) return;
    const saved = localStorage.getItem(`sin:read:${post.id}`);
    if (saved && Number(saved) > 8) {
      savedPctRef.current = Number(saved);
      setShowResume(true);
      setTimeout(() => setShowResume(false), 5000);
    }
  }, [post?.id]);

  function handleResume() {
    const total = document.documentElement.scrollHeight - window.innerHeight;
    window.scrollTo({ top: (savedPctRef.current / 100) * total, behavior: "smooth" });
    setShowResume(false);
  }

  useEffect(() => {
    if (post?.id) recordView(post.id);
  }, [post?.id]);

  useEffect(() => {
    if (post?.id && !!token) {
      recordRead(post.id).catch(() => {});
    }
  }, [post?.id, token]);

  useEffect(() => {
    if (post) {
      setLockedState(post.locked ?? false);
      setPinnedState(post.pinned ?? false);
    }
  }, [post?.id]);

  useEffect(() => {
    if (token && post?.id) {
      getPostSubscriptionStatus(post.id).then(setSubscribed).catch(() => {});
    }
  }, [token, post?.id]);

  async function handleSubscribeToggle() {
    if (!post) return;
    try {
      if (subscribed) {
        await unsubscribePost(post.id);
        setSubscribed(false);
      } else {
        await subscribePost(post.id);
        setSubscribed(true);
      }
    } catch {
      // silently ignore
    }
  }

  const authUsername = useAuthStore((s) => s.username ?? "");
  const canLock = !!token && (
    post?.author_username === authUsername ||
    role === "moderator" ||
    role === "admin"
  );

  if (isLoading) return <Spinner />;
  if (!post) return <p className="text-center text-gray-400 py-12">Post not found.</p>;

  const readingMinutes = post.reading_time_minutes ?? readingTime(post.body ?? "");

  return (
    <div className="xl:grid xl:grid-cols-[1fr_220px] xl:gap-8 max-w-5xl mx-auto">
      <ReadingProgress />
      <SEO
        title={post.title}
        description={post.body?.slice(0, 160).replace(/[#*`]/g, "") ?? ""}
        image={post.cover_image_url ?? undefined}
        url={`${window.location.origin}/posts/${post.slug}`}
        type="article"
        rssHref={`/api/v1/users/${post.author_username}/feed.rss`}
        rssTitle={`Posts by ${post.author_display_name || post.author_username} — SIN`}
      />
      <article className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden min-w-0">
        {post.cover_image_url && (
          <img src={post.cover_image_url} alt="" className="w-full h-64 object-cover" />
        )}
        <div className="p-8">
          <div className="flex flex-wrap gap-1.5 mb-4">
            {post.tags.map((t) => <TagBadge key={t} name={t} />)}
          </div>
          {post.pinned && (
            <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1 mb-2">
              📌 <span>Pinned</span>
            </span>
          )}
          <h1 className="text-3xl font-bold text-gray-900 dark:text-gray-100 mb-4">{post.title}</h1>
          <div className="flex items-center gap-3 mb-8 pb-6 border-b border-gray-100 dark:border-gray-800">
            <div className="w-10 h-10 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold">
              {post.author_display_name?.[0] ?? post.author_username[0]}
            </div>
            <div>
              <Link to={`/users/${post.author_username}`} className="font-medium hover:text-brand">
                {post.author_display_name || post.author_username}
              </Link>
              <p className="text-sm text-gray-400 dark:text-gray-500">
                {timeAgo(post.created_at)}
                <span className="text-xs text-gray-400 dark:text-gray-500 ml-1">&middot; {readingMinutes} min read</span>
                {post.edited_at && (
                  <span className="text-xs text-gray-400 dark:text-gray-500 ml-1">&middot; Edited</span>
                )}
              </p>
            </div>
          </div>
          {/* Reading progress bar */}
          <div data-print="hide" className="sticky top-14 z-40 h-0.5 bg-gray-100 -mx-8 mb-4">
            <div
              className="h-full bg-brand transition-all duration-150"
              style={{ width: `${readProgress}%` }}
            />
          </div>
          {post.sensitive && !showSensitive ? (
            <div className="relative">
              <div className="blur-sm pointer-events-none select-none" aria-hidden>
                <div className="prose dark:prose-invert max-w-none text-gray-700 dark:text-gray-300 leading-relaxed min-h-[200px]">
                  {renderBody(post.body ?? "")}
                </div>
              </div>
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-white/60 dark:bg-gray-900/60 rounded-lg">
                <p className="text-gray-700 dark:text-gray-300 font-medium mb-3">This post contains sensitive content</p>
                <button
                  onClick={() => setShowSensitive(true)}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 text-sm"
                >
                  Show anyway
                </button>
              </div>
            </div>
          ) : (
            <div ref={contentRef} className="prose dark:prose-invert max-w-none text-gray-700 dark:text-gray-300 leading-relaxed">
              {renderBody(post.body ?? "")}
            </div>
          )}
          {post.canonical_url && (
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-4 pt-4 border-t border-gray-100 dark:border-gray-800">
              Originally published at{" "}
              <a href={post.canonical_url} target="_blank" rel="noopener noreferrer" className="text-brand hover:underline">
                {post.canonical_url}
              </a>
            </p>
          )}
        </div>
      </article>

      <aside className="hidden xl:block">
        <div className="sticky top-20">
          <TableOfContents entries={tocEntries} activeId={tocActiveId} />
        </div>
      </aside>

      {/* Everything below the article spans the full width on all screen sizes */}
      <div className="xl:col-span-2">

      <SeriesNav postId={post.id} />

      <div data-print="hide"><RelatedPosts postId={post.id} /></div>

      <div data-print="hide" className="flex gap-3 mt-4 flex-wrap items-center">
        <ReactionBar
          postId={post.id}
          counts={reactionCounts}
          userReactions={userReactions}
          onReact={handleReact}
          onUnreact={handleUnreact}
        />
        <BookmarkButton postId={post.id} />
        <ShareButton
          title={post.title}
          url={window.location.origin + "/posts/" + post.slug}
        />
        <button
          onClick={() => window.print()}
          data-print="hide"
          className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800"
          title="Print"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 17h2a2 2 0 002-2v-4a2 2 0 00-2-2H5a2 2 0 00-2 2v4a2 2 0 002 2h2m2 4h6a2 2 0 002-2v-4a2 2 0 00-2-2H9a2 2 0 00-2 2v4a2 2 0 002 2zm8-12V5a2 2 0 00-2-2H9a2 2 0 00-2 2v4h10z" />
          </svg>
        </button>
        {token && post.author_username !== authUsername && (
          <button
            onClick={handleSubscribeToggle}
            className={`text-xs px-2 py-1 rounded border transition-colors ${
              subscribed
                ? "border-brand text-brand hover:bg-brand/5"
                : "border-gray-300 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-brand hover:text-brand"
            }`}
          >
            {subscribed ? "Subscribed" : "Subscribe to comments"}
          </button>
        )}
        {post.author_username === authUsername && (
          <Link
            to={`/posts/${post.slug}/edit`}
            className="flex items-center gap-1.5 px-3 py-2 border rounded-lg text-sm transition-colors border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-brand/40 hover:text-brand"
          >
            <Pencil className="w-4 h-4" /> Edit
          </Link>
        )}
        {canLock && (
          <button
            onClick={async () => {
              try {
                if (lockedState) {
                  await unlockPost(post.id);
                } else {
                  await lockPost(post.id);
                }
                setLockedState(!lockedState);
                qc.invalidateQueries({ queryKey: ["post", slug] });
              } catch { /* ignore */ }
            }}
            className="flex items-center gap-1.5 px-3 py-2 border rounded-lg text-sm transition-colors border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-600"
            title={lockedState ? "Unlock comments" : "Lock comments"}
          >
            {lockedState ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
            <span>{lockedState ? "Locked" : "Lock"}</span>
          </button>
        )}
        {(role === "admin" || role === "moderator") && (
          <button
            onClick={async () => {
              try {
                if (pinnedState) {
                  await unpinPost(post.id);
                } else {
                  await pinPost(post.id);
                }
                setPinnedState(!pinnedState);
                qc.invalidateQueries({ queryKey: ["post", slug] });
              } catch { /* ignore */ }
            }}
            className={`flex items-center gap-1.5 px-3 py-2 border rounded-lg text-sm transition-colors ${
              pinnedState
                ? "border-brand/40 text-brand bg-brand/5"
                : "border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-gray-300 dark:hover:border-gray-600"
            }`}
            title={pinnedState ? "Unpin post" : "Pin post"}
          >
            <Pin className="w-4 h-4" />
            <span>{pinnedState ? "Pinned" : "Pin"}</span>
          </button>
        )}
        <span className="flex items-center gap-1 text-sm text-gray-500 dark:text-gray-400 ml-auto">
          <MessageCircle className="w-4 h-4" /> {post.comment_count}
        </span>
        <ShareButtons
          url={`${window.location.origin}/posts/${post.slug}`}
          title={post.title}
        />
      </div>

      <div data-print="hide"><ContextNote postId={post.id} /></div>

      {lockedState && (
        <div data-print="hide" className="mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg text-sm text-amber-700 flex items-center gap-2">
          <Lock className="w-4 h-4" />
          Comments are locked on this post.
        </div>
      )}

      {/* Resume reading toast */}
      {showResume && (
        <div data-print="hide" className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-white border border-gray-200 shadow-lg rounded-lg px-4 py-3 text-sm">
          <span className="text-gray-600">Continue where you left off?</span>
          <button onClick={handleResume} className="text-brand font-medium hover:underline">
            Resume
          </button>
          <button onClick={() => setShowResume(false)} className="text-gray-400 hover:text-gray-600">&#x2715;</button>
        </div>
      )}

      <PostComments postId={post.id} locked={lockedState} />
      </div>
    </div>
  );
}
