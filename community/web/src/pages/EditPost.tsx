import { useState, useRef, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getPost, updatePost, schedulePost, unschedulePost } from "@/api/posts";
import { getPostSeries, addPostToSeries, removePostFromSeries } from "@/api/series";
import SeriesSelector from "@/components/SeriesSelector";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";
import { Calendar } from "lucide-react";
import TagInput from "@/components/TagInput";
import { useWordCount } from "@/hooks/useWordCount";
import WordCountBar from "@/components/WordCountBar";
import MarkdownPreview from "@/components/MarkdownPreview";
import MarkdownToolbar from "@/components/MarkdownToolbar";
import MarkdownEditor from "@/components/MarkdownEditor";
import ImageUpload from "@/components/ImageUpload";
import { useAutosave } from "@/hooks/useAutosave";
import type { EditorView } from "@codemirror/view";

function formatScheduled(iso: string): string {
  return new Intl.DateTimeFormat("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(iso));
}

/** Convert an ISO string to the YYYY-MM-DDTHH:mm format required by datetime-local inputs */
function isoToDatetimeLocal(iso: string): string {
  const d = new Date(iso);
  // Pad to ensure correct format
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    d.getFullYear() +
    "-" +
    pad(d.getMonth() + 1) +
    "-" +
    pad(d.getDate()) +
    "T" +
    pad(d.getHours()) +
    ":" +
    pad(d.getMinutes())
  );
}

export default function EditPost() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const { username, role } = useAuthStore();
  const qc = useQueryClient();

  const { data: post, isLoading } = useQuery({
    queryKey: ["post", slug],
    queryFn: () => getPost(slug!),
  });

  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [coverImageUrl, setCoverImageUrl] = useState("");
  const [canonicalUrl, setCanonicalUrl] = useState("");
  const [sensitive, setSensitive] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [autosaveSavedAt, setAutosaveSavedAt] = useState<Date | null>(null);
  const [autosaveError, setAutosaveError] = useState(false);
  const [autosavePending, setAutosavePending] = useState(false);
  const autosaveFadeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const viewRef = useRef<EditorView | null>(null);

  // Series state — tracks what's selected in the dropdown
  const [selectedSeriesId, setSelectedSeriesId] = useState<string | null>(null);
  const [seriesInitialized, setSeriesInitialized] = useState(false);

  // Fetch the series this post currently belongs to (if any)
  const { data: postSeriesInfo } = useQuery({
    queryKey: ["post-series", post?.id],
    queryFn: () => getPostSeries(post!.id),
    enabled: !!post?.id,
    staleTime: 30_000,
  });

  // Pre-select the current series once we have both the post and its series info
  useEffect(() => {
    if (!seriesInitialized && postSeriesInfo !== undefined) {
      setSelectedSeriesId(postSeriesInfo.series?.id ?? null);
      setSeriesInitialized(true);
    }
  }, [postSeriesInfo, seriesInitialized]);

  const [tab, setTab] = useState<"write" | "preview">("write");

  // Scheduling state
  const [showSchedule, setShowSchedule] = useState(false);
  const [scheduledAt, setScheduledAt] = useState("");
  const [scheduling, setScheduling] = useState(false);
  const [unscheduling, setUnscheduling] = useState(false);

  const draftTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Ref so the Ctrl+Enter handler always calls the latest version of handleSave
  const handleSaveRef = useRef<() => void>(() => {});

  // Ctrl+Enter to save — registered before early returns so hook rules are satisfied
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleSaveRef.current();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Pre-fill form from loaded post, then check for localStorage override
  useEffect(() => {
    if (post) {
      setTitle(post.title);
      setBody(post.body ?? "");
      setTags(post.tags);
      setCoverImageUrl(post.cover_image_url ?? "");
      setCanonicalUrl(post.canonical_url ?? "");
      setSensitive(post.sensitive ?? false);

      // Pre-fill scheduledAt from existing scheduled_at if present
      if (post.scheduled_at) {
        setScheduledAt(isoToDatetimeLocal(post.scheduled_at));
      }

      // Restore any in-progress draft from localStorage
      try {
        const draftKey = `sin:draft:edit:${post.id}`;
        const raw = localStorage.getItem(draftKey);
        if (raw) {
          const draft = JSON.parse(raw);
          if (draft.title !== undefined) setTitle(draft.title);
          if (draft.body !== undefined) setBody(draft.body);
          if (draft.tags !== undefined) {
            // Support legacy string drafts and current array drafts
            if (Array.isArray(draft.tags)) {
              setTags(draft.tags);
            } else if (typeof draft.tags === "string") {
              setTags(draft.tags.split(",").map((t: string) => t.trim()).filter(Boolean));
            }
          }
          if (draft.coverImageUrl !== undefined) setCoverImageUrl(draft.coverImageUrl);
          if (draft.canonicalUrl !== undefined) setCanonicalUrl(draft.canonicalUrl);
        }
      } catch {
        // ignore malformed draft
      }
    }
  }, [post?.id]);

  // Debounced localStorage draft save (only after post is loaded so we have post.id)
  useEffect(() => {
    if (!post?.id) return;
    const draftKey = `sin:draft:edit:${post.id}`;
    if (draftTimerRef.current) clearTimeout(draftTimerRef.current);
    draftTimerRef.current = setTimeout(() => {
      try {
        localStorage.setItem(draftKey, JSON.stringify({ title, body, tags, coverImageUrl, canonicalUrl }));
      } catch {
        // ignore storage errors
      }
    }, 2000);
    return () => {
      if (draftTimerRef.current) clearTimeout(draftTimerRef.current);
    };
  }, [title, body, tags, coverImageUrl, canonicalUrl, post?.id]);

  // Mark autosave as pending whenever content changes (post must be loaded and a draft).
  useEffect(() => {
    if (!post?.id || post.state !== "draft") return;
    if (!title.trim() && !body.trim()) return;
    setAutosavePending(true);
    setAutosaveSavedAt(null);
    setAutosaveError(false);
  }, [title, body, tags, post?.id, post?.state]);

  useAutosave({
    postId: post?.state === "draft" ? (post?.id ?? null) : null,
    title,
    body,
    tags,
    enabled: post?.state === "draft",
    onSave: (savedAt) => {
      setAutosavePending(false);
      setAutosaveSavedAt(savedAt);
      setAutosaveError(false);
      if (autosaveFadeTimer.current) clearTimeout(autosaveFadeTimer.current);
      autosaveFadeTimer.current = setTimeout(() => setAutosaveSavedAt(null), 3000);
    },
    onError: () => {
      setAutosavePending(false);
      setAutosaveError(true);
    },
  });

  const wordCountStats = useWordCount(body);

  if (isLoading) return <Spinner />;
  if (!post) return <p className="text-center text-gray-400 py-12">Post not found.</p>;

  const canEdit = post.author_username === username || role === "moderator" || role === "admin";
  if (!canEdit) {
    navigate(`/posts/${slug}`, { replace: true });
    return null;
  }

  const scheduleValid = scheduledAt && new Date(scheduledAt) > new Date();

  async function handleSave() {
    if (!title.trim() || !post) return;
    setSaving(true);
    setError(null);
    try {
      await updatePost(post.id, { title, body, tags, cover_image_url: coverImageUrl || undefined, canonical_url: canonicalUrl || undefined, sensitive });
      localStorage.removeItem(`sin:draft:edit:${post.id}`);
      // Sync series assignment
      const currentSeriesId = postSeriesInfo?.series?.id ?? null;
      if (selectedSeriesId && selectedSeriesId !== currentSeriesId) {
        // Added to a new series (or switched series)
        await addPostToSeries(selectedSeriesId, post.id, 0).catch(() => {});
      } else if (!selectedSeriesId && currentSeriesId) {
        // Removed from series
        await removePostFromSeries(currentSeriesId, post.id).catch(() => {});
      }
      navigate(`/posts/${post.slug}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to save.");
    } finally {
      setSaving(false);
    }
  }
  // Keep ref in sync so the Ctrl+Enter listener always calls the latest version
  handleSaveRef.current = handleSave;

  async function handleSchedule() {
    if (!scheduleValid || !post) return;
    setScheduling(true);
    setError(null);
    try {
      // Save latest content first
      await updatePost(post.id, { title, body, tags, cover_image_url: coverImageUrl || undefined, canonical_url: canonicalUrl || undefined, sensitive });
      await schedulePost(post.id, new Date(scheduledAt).toISOString());
      localStorage.removeItem(`sin:draft:edit:${post.id}`);
      qc.invalidateQueries({ queryKey: ["post", slug] });
      qc.invalidateQueries({ queryKey: ["my-posts"] });
      navigate("/me/posts");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to schedule.");
    } finally {
      setScheduling(false);
    }
  }

  async function handleUnschedule() {
    if (!post) return;
    setUnscheduling(true);
    setError(null);
    try {
      await unschedulePost(post.id);
      qc.invalidateQueries({ queryKey: ["post", slug] });
      qc.invalidateQueries({ queryKey: ["my-posts"] });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to remove schedule.");
    } finally {
      setUnscheduling(false);
    }
  }

  return (
    <div className="max-w-3xl mx-auto">
      <div className="bg-white border border-gray-200 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between mb-2">
          <h1 className="text-lg font-semibold text-gray-800">Edit post</h1>
          <button
            onClick={() => navigate(`/posts/${slug}`)}
            className="text-sm text-gray-400 hover:text-gray-600"
          >
            Cancel
          </button>
        </div>
        <input
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Post title…"
          className="w-full text-2xl font-bold border-none outline-none placeholder-gray-300"
        />
        {post.state === "draft" && (
          <div className="min-h-[1.25rem]">
            {autosavePending && !autosaveError && (
              <span className="text-xs text-gray-400">Saving…</span>
            )}
            {!autosavePending && autosaveSavedAt && !autosaveError && (
              <span className="text-xs text-green-600 transition-opacity duration-1000">
                Draft saved at{" "}
                {autosaveSavedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
              </span>
            )}
            {autosaveError && (
              <span className="text-xs text-red-500">Autosave failed</span>
            )}
          </div>
        )}
        <TagInput
          value={tags}
          onChange={setTags}
          maxTags={5}
        />
        {/* Series */}
        <SeriesSelector
          postId={post.id}
          value={selectedSeriesId}
          onChange={setSelectedSeriesId}
        />
        {/* Cover image */}
        <ImageUpload value={coverImageUrl} onChange={setCoverImageUrl} />
        <input
          type="url"
          value={canonicalUrl}
          onChange={(e) => setCanonicalUrl(e.target.value)}
          placeholder="Canonical URL (if crossposting from your blog)"
          className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
        />
        {/* Write / Preview tab bar */}
        <div className="flex border-b border-gray-200 dark:border-gray-700 mb-0">
          {(["write", "preview"] as const).map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                tab === t
                  ? "border-indigo-500 text-indigo-600 dark:text-indigo-400"
                  : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
              }`}
            >
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>
        {tab === "write" ? (
          <div>
            <MarkdownToolbar viewRef={viewRef} />
            <MarkdownEditor value={body} onChange={setBody} viewRef={viewRef} />
          </div>
        ) : (
          <div className="min-h-[300px] p-3 border border-t-0 border-gray-300 dark:border-gray-600 rounded-b-md bg-white dark:bg-gray-900">
            {body ? (
              <MarkdownPreview content={body} />
            ) : (
              <p className="text-gray-400 dark:text-gray-500 italic text-sm">Nothing to preview.</p>
            )}
          </div>
        )}
        <WordCountBar {...wordCountStats} />

        {/* Scheduled status banner */}
        {post.state === "scheduled" && post.scheduled_at && !showSchedule && (
          <div className="flex items-center gap-3 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
            <Calendar className="w-4 h-4 text-indigo-500 shrink-0" />
            <div className="flex-1">
              <p className="text-sm font-medium text-indigo-700">
                Scheduled for: {formatScheduled(post.scheduled_at)}
              </p>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  if (post.scheduled_at) setScheduledAt(isoToDatetimeLocal(post.scheduled_at));
                  setShowSchedule(true);
                }}
                className="px-3 py-1 text-xs border border-indigo-300 text-indigo-600 rounded-md hover:bg-indigo-100 transition-colors"
              >
                Change schedule
              </button>
              <button
                type="button"
                onClick={handleUnschedule}
                disabled={unscheduling}
                className="px-3 py-1 text-xs border border-red-200 text-red-500 rounded-md hover:bg-red-50 disabled:opacity-50 transition-colors"
              >
                {unscheduling ? "Removing…" : "Remove schedule"}
              </button>
            </div>
          </div>
        )}

        {/* Schedule panel — shown when adding or changing a schedule */}
        {showSchedule && (
          <div className="p-3 bg-indigo-50 border border-indigo-200 rounded-lg space-y-2">
            <p className="text-xs font-medium text-indigo-700">Schedule publication</p>
            <div className="flex items-center gap-3 flex-wrap">
              <Calendar className="w-4 h-4 text-indigo-400 shrink-0" />
              <input
                type="datetime-local"
                value={scheduledAt}
                min={new Date(Date.now() + 60_000).toISOString().slice(0, 16)}
                onChange={(e) => setScheduledAt(e.target.value)}
                className="text-sm border border-indigo-200 rounded-md px-2 py-1 focus:outline-none focus:ring-2 focus:ring-brand/40 bg-white"
              />
              <button
                type="button"
                onClick={handleSchedule}
                disabled={scheduling || !title.trim() || !scheduleValid}
                className="px-4 py-1 text-xs bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 transition-colors"
              >
                {scheduling ? "Scheduling…" : "Schedule"}
              </button>
              {scheduledAt && !scheduleValid && (
                <span className="text-xs text-red-500">Must be in the future</span>
              )}
            </div>
            <button
              type="button"
              onClick={() => { setShowSchedule(false); setScheduledAt(post.scheduled_at ? isoToDatetimeLocal(post.scheduled_at) : ""); }}
              className="text-xs text-indigo-400 hover:text-indigo-600"
            >
              Cancel
            </button>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
          <input
            type="checkbox"
            checked={sensitive}
            onChange={e => setSensitive(e.target.checked)}
            className="rounded border-gray-300"
          />
          Mark as sensitive content
        </label>

        {error && <p className="text-sm text-red-500">{error}</p>}

        <div className="flex gap-3 flex-wrap">
          <button
            onClick={handleSave}
            disabled={saving || !title.trim()}
            className="px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
          >
            {saving ? "Saving…" : "Save changes"}
          </button>
          {/* Show "Schedule for later" only when post is not already scheduled or the panel is not already open */}
          {post.state !== "scheduled" && !showSchedule && (
            <button
              type="button"
              onClick={() => setShowSchedule(true)}
              disabled={!title.trim()}
              className="px-5 py-2 border border-indigo-300 text-indigo-600 text-sm rounded-lg hover:bg-indigo-50 disabled:opacity-50 transition-colors flex items-center gap-1.5"
            >
              <Calendar className="w-4 h-4" /> Schedule for later
            </button>
          )}
          <button
            onClick={() => navigate(`/posts/${slug}`)}
            className="px-5 py-2 border border-gray-300 text-sm rounded-lg hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <Link
            to={`/posts/${slug}/revisions`}
            className="ml-auto text-sm text-gray-400 hover:text-brand self-center"
          >
            View history
          </Link>
        </div>
      </div>
    </div>
  );
}
