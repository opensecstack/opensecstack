import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Calendar } from "lucide-react";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";
import {
  getScheduledPosts,
  schedulePost,
  unschedulePost,
  type ScheduledPost,
} from "@/api/posts";

// Returns e.g. "Jun 15" and "in 3 days" / "in 2 hours" / "overdue"
function formatScheduled(iso: string): { date: string; relative: string; soon: boolean } {
  const target = new Date(iso);
  const now = new Date();
  const diffMs = target.getTime() - now.getTime();
  const diffMins = Math.round(diffMs / 60_000);

  const date = target.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });

  let relative: string;
  if (diffMins < 0) {
    relative = "overdue";
  } else if (diffMins < 60) {
    relative = `in ${diffMins}m`;
  } else if (diffMins < 60 * 24) {
    const h = Math.floor(diffMins / 60);
    relative = `in ${h}h`;
  } else {
    const d = Math.floor(diffMins / (60 * 24));
    relative = `in ${d} day${d !== 1 ? "s" : ""}`;
  }

  const soon = diffMs >= 0 && diffMs <= 24 * 60 * 60 * 1000;

  return { date, relative, soon };
}

function ScheduledRow({ post, onRemoved }: { post: ScheduledPost; onRemoved: (id: string) => void }) {
  const qc = useQueryClient();
  const [rescheduling, setRescheduling] = useState(false);
  const [newTime, setNewTime] = useState("");
  const [saving, setSaving] = useState(false);
  const [unscheduling, setUnscheduling] = useState(false);

  const { date, relative, soon } = formatScheduled(post.scheduled_at);

  async function handleReschedule() {
    if (!newTime) return;
    setSaving(true);
    try {
      // datetime-local gives "YYYY-MM-DDTHH:mm", convert to RFC3339
      const iso = new Date(newTime).toISOString();
      await schedulePost(post.id, iso);
      qc.invalidateQueries({ queryKey: ["scheduled-posts"] });
      setRescheduling(false);
      setNewTime("");
    } finally {
      setSaving(false);
    }
  }

  async function handleUnschedule() {
    setUnscheduling(true);
    try {
      // optimistic: remove immediately
      onRemoved(post.id);
      await unschedulePost(post.id);
    } catch {
      // on failure, let the query refetch to restore the row
      qc.invalidateQueries({ queryKey: ["scheduled-posts"] });
    } finally {
      setUnscheduling(false);
    }
  }

  // Minimum datetime-local value: now (rounded up to next minute)
  const minDatetime = (() => {
    const d = new Date(Date.now() + 60_000);
    d.setSeconds(0, 0);
    return d.toISOString().slice(0, 16);
  })();

  return (
    <div className="flex items-center gap-4 bg-white border border-gray-200 rounded-lg p-4">
      {/* Cover thumbnail */}
      <div className="shrink-0 w-16 h-12 rounded overflow-hidden bg-gray-100">
        {post.cover_image_url ? (
          <img
            src={post.cover_image_url}
            alt=""
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center text-gray-300">
            <Calendar size={20} />
          </div>
        )}
      </div>

      {/* Title */}
      <div className="flex-1 min-w-0">
        <Link
          to={`/posts/${post.slug}/edit`}
          className="font-medium text-gray-900 hover:text-brand line-clamp-1"
        >
          {post.title}
        </Link>

        {/* Scheduled time + relative */}
        <div className="flex items-center gap-2 mt-1">
          <span className="text-xs text-gray-500">
            {date} &middot; {relative}
          </span>
          {soon && (
            <span className="px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-700 rounded">
              Soon
            </span>
          )}
        </div>

        {/* Inline reschedule picker */}
        {rescheduling && (
          <div className="flex items-center gap-2 mt-2">
            <input
              type="datetime-local"
              min={minDatetime}
              value={newTime}
              onChange={(e) => setNewTime(e.target.value)}
              className="text-xs border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-brand"
            />
            <button
              onClick={handleReschedule}
              disabled={!newTime || saving}
              className="px-2.5 py-1 text-xs bg-brand text-white rounded hover:bg-brand-dark disabled:opacity-50 transition-colors"
            >
              {saving ? "Saving…" : "Save"}
            </button>
            <button
              onClick={() => { setRescheduling(false); setNewTime(""); }}
              className="text-xs text-gray-400 hover:text-gray-600"
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 shrink-0">
        <Link
          to={`/posts/${post.slug}/edit`}
          className="px-3 py-1.5 text-xs border border-gray-200 rounded-lg hover:bg-gray-50 text-gray-600 transition-colors"
        >
          Edit
        </Link>
        <button
          onClick={() => setRescheduling((r) => !r)}
          className="px-3 py-1.5 text-xs border border-indigo-200 text-indigo-600 rounded-lg hover:bg-indigo-50 transition-colors"
        >
          Reschedule
        </button>
        <button
          onClick={handleUnschedule}
          disabled={unscheduling}
          className="px-3 py-1.5 text-xs border border-gray-200 text-gray-400 hover:border-red-300 hover:text-red-500 rounded-lg transition-colors disabled:opacity-50"
        >
          Unschedule
        </button>
      </div>
    </div>
  );
}

export default function ScheduledPosts() {
  const { token } = useAuthStore();
  const navigate = useNavigate();
  const qc = useQueryClient();

  if (!token) {
    navigate("/login", { replace: true });
    return null;
  }

  const { data, isLoading } = useQuery({
    queryKey: ["scheduled-posts"],
    queryFn: getScheduledPosts,
  });

  const posts = data?.posts ?? [];

  function handleRemoved(id: string) {
    qc.setQueryData(["scheduled-posts"], (old: typeof data) => {
      if (!old) return old;
      return { ...old, posts: old.posts.filter((p) => p.id !== id), total: old.total - 1 };
    });
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h1 className="text-2xl font-bold">Scheduled Posts</h1>
          <p className="text-sm text-gray-500 mt-0.5">Posts queued for automatic publishing</p>
        </div>
        <Link
          to="/me/posts"
          className="text-sm text-gray-500 hover:text-gray-700 transition-colors"
        >
          &larr; All posts
        </Link>
      </div>

      <div className="mt-6">
        {isLoading ? (
          <Spinner />
        ) : posts.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <Calendar size={40} className="text-gray-300 mb-4" />
            <p className="text-gray-500 font-medium">No scheduled posts</p>
            <p className="text-sm text-gray-400 mt-1">
              Schedule a post from the editor.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {posts.map((post) => (
              <ScheduledRow key={post.id} post={post} onRemoved={handleRemoved} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
