import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { getMyPosts } from "@/api/users";
import { deletePost, publishPost, unschedulePost } from "@/api/posts";
import { pinPost, unpinPost } from "@/api/pin";
import { archivePost, unarchivePost } from "@/api/archive";
import { getPostAnalytics } from "@/api/analytics";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";
import Spinner from "@/components/Spinner";
import AnalyticsChart from "@/components/AnalyticsChart";
import { BarChart2 } from "lucide-react";
import EmptyState, { PostsEmptyIcon } from "@/components/EmptyState";
import { useState } from "react";
import type { Post } from "@/api/posts";

type Tab = "published" | "draft" | "scheduled" | "archived";

function StateBadge({ state }: { state: string }) {
  const cls: Record<string, string> = {
    published: "bg-green-100 text-green-700",
    draft: "bg-gray-100 text-gray-600",
    scheduled: "bg-indigo-100 text-indigo-700",
    archived: "bg-slate-100 text-slate-600",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${cls[state] ?? "bg-gray-100 text-gray-500"}`}>
      {state}
    </span>
  );
}

function PostRow({
  post,
  onDelete,
  onArchive,
  onUnarchive,
  onPinToggled,
}: {
  post: Post;
  onDelete: (id: string) => void;
  onArchive?: (id: string) => void;
  onUnarchive?: (id: string) => void;
  onPinToggled?: (id: string, pinned: boolean) => void;
}) {
  const navigate = useNavigate();
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [confirmingArchive, setConfirmingArchive] = useState(false);
  const [analyticsOpen, setAnalyticsOpen] = useState(false);
  const qc = useQueryClient();

  const { data: analyticsData, isLoading: analyticsLoading } = useQuery({
    queryKey: ["analytics", post.id],
    queryFn: () => getPostAnalytics(post.id),
    enabled: analyticsOpen && post.state === "published",
  });

  async function handleDelete() {
    if (!confirmingDelete) { setConfirmingDelete(true); return; }
    await deletePost(post.id);
    onDelete(post.id);
    setConfirmingDelete(false);
  }

  async function handlePublish() {
    await publishPost(post.id);
    qc.invalidateQueries({ queryKey: ["my-posts"] });
  }

  async function handleUnschedule() {
    await unschedulePost(post.id);
    qc.invalidateQueries({ queryKey: ["my-posts"] });
  }

  async function handleArchive() {
    if (!confirmingArchive) { setConfirmingArchive(true); return; }
    await archivePost(post.id);
    setConfirmingArchive(false);
    if (onArchive) onArchive(post.id);
  }

  async function handleUnarchive() {
    await unarchivePost(post.id);
    if (onUnarchive) onUnarchive(post.id);
  }

  async function handlePinToggle() {
    if (post.pinned) {
      await unpinPost(post.id);
      if (onPinToggled) onPinToggled(post.id, false);
    } else {
      await pinPost(post.id);
      if (onPinToggled) onPinToggled(post.id, true);
    }
  }

  return (
    <div className="rounded-lg overflow-hidden border border-gray-200">
      <div className="bg-white p-4 flex items-start gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <StateBadge state={post.state} />
            {post.state === "scheduled" && post.scheduled_at && (
              <span className="text-xs text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full">
                📅 {new Date(post.scheduled_at).toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" })}
              </span>
            )}
          </div>
          <Link
            to={`/posts/${post.slug}`}
            className="font-semibold text-gray-900 hover:text-brand line-clamp-1"
          >
            {post.title}
          </Link>
          <p className="text-xs text-gray-400 mt-0.5">
            Updated {timeAgo(post.updated_at)}
            {post.state === "published" && (
              <span className="ml-2">{post.views ?? 0} views · {post.reaction_count} reactions</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {post.state === "published" && (
            <>
              <button
                onClick={handlePinToggle}
                title={post.pinned ? "Unpin post" : "Pin to profile"}
                className={`p-1.5 rounded-lg border transition-colors ${
                  post.pinned
                    ? "border-brand text-brand bg-indigo-50"
                    : "border-gray-200 text-gray-400 hover:border-brand hover:text-brand"
                }`}
              >
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M16 3a1 1 0 0 1 .707 1.707L15.414 6l1.293 1.293a1 1 0 0 1-1.414 1.414L14 7.414l-4.293 4.293A5.003 5.003 0 0 1 9 14H8l-2 2H4v-2l2-2v-1a5.003 5.003 0 0 1 2.293-.707l4.293-4.293-1.293-1.293a1 1 0 0 1 1.414-1.414L14 5.414l1.293-1.293A1 1 0 0 1 16 3z"/>
                </svg>
              </button>
              <button
                onClick={() => setAnalyticsOpen((o) => !o)}
                title="View analytics"
                className={`p-1.5 rounded-lg border transition-colors ${
                  analyticsOpen
                    ? "border-indigo-300 text-indigo-600 bg-indigo-50"
                    : "border-gray-200 text-gray-400 hover:border-indigo-300 hover:text-indigo-500"
                }`}
              >
                <BarChart2 size={14} />
              </button>
            </>
          )}
          {post.state !== "archived" && (
            <button
              onClick={() => navigate(`/posts/${post.slug}/edit`)}
              className="px-3 py-1.5 text-xs border border-gray-200 rounded-lg hover:bg-gray-50 text-gray-600 transition-colors"
            >
              Edit
            </button>
          )}
          {post.state === "draft" && (
            <button
              onClick={handlePublish}
              className="px-3 py-1.5 text-xs bg-brand text-white rounded-lg hover:bg-brand-dark transition-colors"
            >
              Publish
            </button>
          )}
          {post.state === "scheduled" && (
            <button
              onClick={handleUnschedule}
              className="px-3 py-1.5 text-xs border border-indigo-300 text-indigo-600 rounded-lg hover:bg-indigo-50 transition-colors"
            >
              Unschedule
            </button>
          )}
          {(post.state === "published" || post.state === "scheduled") && (
            <>
              <button
                onClick={handleArchive}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  confirmingArchive
                    ? "bg-slate-500 text-white hover:bg-slate-600"
                    : "border border-gray-200 text-gray-400 hover:border-slate-400 hover:text-slate-600"
                }`}
              >
                {confirmingArchive ? "Confirm?" : "Archive"}
              </button>
              {confirmingArchive && (
                <button
                  onClick={() => setConfirmingArchive(false)}
                  className="text-xs text-gray-400 hover:text-gray-600"
                >
                  Cancel
                </button>
              )}
            </>
          )}
          {post.state === "archived" && (
            <button
              onClick={handleUnarchive}
              className="px-3 py-1.5 text-xs border border-slate-300 text-slate-600 rounded-lg hover:bg-slate-50 transition-colors"
            >
              Unarchive
            </button>
          )}
          {post.state !== "archived" && (
            <>
              <button
                onClick={handleDelete}
                className={`px-3 py-1.5 text-xs rounded-lg transition-colors ${
                  confirmingDelete
                    ? "bg-red-500 text-white hover:bg-red-600"
                    : "border border-gray-200 text-gray-400 hover:border-red-300 hover:text-red-500"
                }`}
              >
                {confirmingDelete ? "Confirm?" : "Delete"}
              </button>
              {confirmingDelete && (
                <button
                  onClick={() => setConfirmingDelete(false)}
                  className="text-xs text-gray-400 hover:text-gray-600"
                >
                  Cancel
                </button>
              )}
            </>
          )}
        </div>
      </div>

      {analyticsOpen && post.state === "published" && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3">
          {analyticsLoading ? (
            <p className="text-xs text-gray-400 py-2">Loading analytics...</p>
          ) : analyticsData ? (
            <AnalyticsChart days={analyticsData.days} totalViews={analyticsData.total_views} />
          ) : (
            <p className="text-xs text-red-400 py-2">Failed to load analytics.</p>
          )}
        </div>
      )}
    </div>
  );
}

export default function MyPosts() {
  const { token } = useAuthStore();
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("published");
  const qc = useQueryClient();

  if (!token) {
    navigate("/login", { replace: true });
    return null;
  }

  const { data, isLoading } = useQuery({
    queryKey: ["my-posts"],
    queryFn: () => getMyPosts(100),
  });

  const posts = data?.posts ?? [];
  const byState: Record<Tab, Post[]> = {
    published: posts.filter((p) => p.state === "published"),
    draft: posts.filter((p) => p.state === "draft"),
    scheduled: posts.filter((p) => p.state === "scheduled"),
    archived: posts.filter((p) => p.state === "archived"),
  };

  const tabs: { key: Tab; label: string }[] = [
    { key: "published", label: `Published (${byState.published.length})` },
    { key: "scheduled", label: `Scheduled (${byState.scheduled.length})` },
    { key: "draft", label: `Drafts (${byState.draft.length})` },
    { key: "archived", label: `Archived (${byState.archived.length})` },
  ];

  function handleDeleted(id: string) {
    qc.setQueryData(["my-posts"], (old: typeof data) => {
      if (!old) return old;
      return { ...old, posts: old.posts.filter((p) => p.id !== id) };
    });
  }

  function handleArchived(id: string) {
    qc.setQueryData(["my-posts"], (old: typeof data) => {
      if (!old) return old;
      return {
        ...old,
        posts: old.posts.map((p) =>
          p.id === id ? { ...p, state: "archived" as const } : p
        ),
      };
    });
  }

  function handleUnarchived(id: string) {
    qc.setQueryData(["my-posts"], (old: typeof data) => {
      if (!old) return old;
      return {
        ...old,
        posts: old.posts.map((p) =>
          p.id === id ? { ...p, state: "draft" as const } : p
        ),
      };
    });
  }

  function handlePinToggled(id: string, pinned: boolean) {
    qc.setQueryData(["my-posts"], (old: typeof data) => {
      if (!old) return old;
      return {
        ...old,
        // If pinning, unpin all others first (only one pinned post at a time)
        posts: old.posts.map((p) =>
          p.id === id
            ? { ...p, pinned }
            : pinned
            ? { ...p, pinned: false }
            : p
        ),
      };
    });
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">My Posts</h1>
          {byState.scheduled.length > 0 && (
            <Link
              to="/me/scheduled"
              className="text-sm text-indigo-600 hover:text-indigo-800 font-medium transition-colors"
            >
              View scheduled ({byState.scheduled.length})
            </Link>
          )}
        </div>
        <Link
          to="/new"
          className="px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
        >
          Write new post
        </Link>
      </div>

      <div className="flex gap-1 mb-4 border-b border-gray-200">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              tab === t.key
                ? "border-b-2 border-brand text-brand -mb-px"
                : "text-gray-500 hover:text-gray-700"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {isLoading ? (
        <Spinner />
      ) : (
        <div className="space-y-3">
          {byState[tab].length === 0 ? (
            tab === "published" ? (
              <EmptyState
                icon={<PostsEmptyIcon />}
                title="No posts yet"
                description="Start writing your first post"
                action={{ label: "Write a post", href: "/new" }}
              />
            ) : tab === "draft" ? (
              <EmptyState
                icon={<PostsEmptyIcon />}
                title="No drafts"
                description="Posts you save without publishing will appear here"
              />
            ) : tab === "scheduled" ? (
              <EmptyState
                icon={<PostsEmptyIcon />}
                title="No scheduled posts"
                description="Schedule a post to publish it at a specific time"
              />
            ) : (
              <EmptyState
                icon={<PostsEmptyIcon />}
                title="No archived posts"
                description="Archived posts are hidden from the public feed"
              />
            )
          ) : (
            byState[tab].map((p) => (
              <PostRow
                key={p.id}
                post={p}
                onDelete={handleDeleted}
                onArchive={handleArchived}
                onUnarchive={handleUnarchived}
                onPinToggled={handlePinToggled}
              />
            ))
          )}
        </div>
      )}
    </div>
  );
}
