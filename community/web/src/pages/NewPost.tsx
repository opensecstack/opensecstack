import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { createPost, updatePost, publishPost, schedulePost } from "@/api/posts";
import { addPostToSeries } from "@/api/series";
import { listTemplates, createTemplate } from "@/api/templates";
import type { PostTemplate } from "@/api/templates";
import { Calendar, ChevronDown } from "lucide-react";
import TagInput from "@/components/TagInput";
import SeriesSelector from "@/components/SeriesSelector";
import { useWordCount } from "@/hooks/useWordCount";
import WordCountBar from "@/components/WordCountBar";
import MarkdownPreview from "@/components/MarkdownPreview";
import MarkdownToolbar from "@/components/MarkdownToolbar";
import MarkdownEditor from "@/components/MarkdownEditor";
import ImageUpload from "@/components/ImageUpload";
import { useAuthStore } from "@/state/auth";
import { useAutosave } from "@/hooks/useAutosave";
import type { EditorView } from "@codemirror/view";

const DRAFT_KEY = "sin:draft:new";

export default function NewPost() {
  const navigate = useNavigate();
  const { token } = useAuthStore();
  const isLoggedIn = !!token;

  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [tags, setTags] = useState<string[]>([]);
  const [coverImageUrl, setCoverImageUrl] = useState("");
  const [canonicalUrl, setCanonicalUrl] = useState("");
  const [scheduledAt, setScheduledAt] = useState("");
  const [showSchedule, setShowSchedule] = useState(false);
  const [sensitive, setSensitive] = useState(false);
  const [seriesId, setSeriesId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedId, setSavedId] = useState<string | null>(null);
  const [savedSlug, setSavedSlug] = useState<string | null>(null);
  const [autosaveSavedAt, setAutosaveSavedAt] = useState<Date | null>(null);
  const [autosaveError, setAutosaveError] = useState(false);
  const [autosavePending, setAutosavePending] = useState(false);
  const autosaveFadeTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const viewRef = useRef<EditorView | null>(null);

  const [tab, setTab] = useState<"write" | "preview">("write");

  // Template picker state
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);
  const templatePickerRef = useRef<HTMLDivElement>(null);

  // Save-as-template state
  const [showSaveTemplate, setShowSaveTemplate] = useState(false);
  const [templateName, setTemplateName] = useState("");
  const [templateSaving, setTemplateSaving] = useState(false);
  const [templateToast, setTemplateToast] = useState(false);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const savedIdRef = useRef<string | null>(null);
  const draftTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  savedIdRef.current = savedId;

  // Fetch templates (only when logged in)
  const { data: templates = [] } = useQuery<PostTemplate[]>({
    queryKey: ["templates"],
    queryFn: listTemplates,
    enabled: isLoggedIn,
    staleTime: 30_000,
  });

  // Close template picker on outside click
  useEffect(() => {
    if (!showTemplatePicker) return;
    function handleClick(e: MouseEvent) {
      if (templatePickerRef.current && !templatePickerRef.current.contains(e.target as Node)) {
        setShowTemplatePicker(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, [showTemplatePicker]);

  // Restore localStorage draft on mount
  useEffect(() => {
    try {
      const raw = localStorage.getItem(DRAFT_KEY);
      if (raw) {
        const draft = JSON.parse(raw);
        if (draft.title) setTitle(draft.title);
        if (draft.body) setBody(draft.body);
        if (draft.tags) {
          // Support legacy string drafts and current array drafts
          if (Array.isArray(draft.tags)) {
            setTags(draft.tags);
          } else if (typeof draft.tags === "string") {
            setTags(draft.tags.split(",").map((t: string) => t.trim()).filter(Boolean));
          }
        }
        if (draft.coverImageUrl) setCoverImageUrl(draft.coverImageUrl);
        if (draft.canonicalUrl) setCanonicalUrl(draft.canonicalUrl);
      }
    } catch {
      // ignore malformed draft
    }
  }, []);

  // Debounced localStorage draft save
  useEffect(() => {
    if (draftTimerRef.current) clearTimeout(draftTimerRef.current);
    draftTimerRef.current = setTimeout(() => {
      try {
        localStorage.setItem(DRAFT_KEY, JSON.stringify({ title, body, tags, coverImageUrl, canonicalUrl, sensitive }));
      } catch {
        // ignore storage errors
      }
    }, 2000);
    return () => {
      if (draftTimerRef.current) clearTimeout(draftTimerRef.current);
    };
  }, [title, body, tags, coverImageUrl, canonicalUrl, sensitive]);

  // Wire autosave — only fires once the post has been saved once (savedId is set).
  // The "pending" state is tracked locally so we can show "Saving…" while debouncing.
  useEffect(() => {
    if (!savedId || (!title.trim() && !body.trim())) return;
    setAutosavePending(true);
    setAutosaveSavedAt(null);
    setAutosaveError(false);
  }, [title, body, tags, savedId]);

  useAutosave({
    postId: savedId,
    title,
    body,
    tags,
    enabled: true,
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

  useEffect(() => {
    function onBeforeUnload(e: BeforeUnloadEvent) {
      if (!savedIdRef.current && title.trim()) {
        e.preventDefault();
      }
    }
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [title]);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleSave("publish");
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [title, body, tags, coverImageUrl, canonicalUrl, scheduledAt, sensitive]);

  async function handleSave(mode: "draft" | "publish" | "schedule") {
    if (!title.trim()) return;
    setSaving(true);
    try {
      const cover = coverImageUrl || undefined;
      const canonical = canonicalUrl || undefined;
      let id = savedIdRef.current;
      let slug = savedSlug;

      if (id) {
        await updatePost(id, { title, body, tags, cover_image_url: cover, canonical_url: canonical, sensitive });
      } else {
        const result = await createPost({ title, body, tags, cover_image_url: cover, canonical_url: canonical, sensitive });
        id = result.id;
        slug = result.slug;
        setSavedId(id);
        setSavedSlug(slug);
        // Assign to series immediately after creation, before publish/redirect
        if (seriesId) {
          await addPostToSeries(seriesId, id, 0).catch(() => {});
        }
      }

      if (mode === "publish") {
        await publishPost(id!);
        localStorage.removeItem(DRAFT_KEY);
        navigate(`/posts/${slug}`);
      } else if (mode === "schedule" && scheduledAt) {
        await schedulePost(id!, new Date(scheduledAt).toISOString());
        localStorage.removeItem(DRAFT_KEY);
        navigate("/me/posts");
      } else {
        localStorage.removeItem(DRAFT_KEY);
        navigate(`/posts/${slug}`);
      }
    } finally {
      setSaving(false);
    }
  }

  function applyTemplate(tpl: PostTemplate) {
    const formHasContent = title.trim() || body.trim() || tags.length > 0;
    if (formHasContent) {
      if (!window.confirm(`Load template "${tpl.name}"? This will replace your current title, body, and tags.`)) {
        return;
      }
    }
    setTitle(tpl.title);
    setBody(tpl.body);
    setTags(tpl.tags);
    setShowTemplatePicker(false);
  }

  async function handleSaveTemplate() {
    if (!templateName.trim()) return;
    setTemplateSaving(true);
    try {
      await createTemplate({ name: templateName.trim(), title, body, tags });
      setShowSaveTemplate(false);
      setTemplateName("");
      setTemplateToast(true);
      if (toastTimer.current) clearTimeout(toastTimer.current);
      toastTimer.current = setTimeout(() => setTemplateToast(false), 2500);
    } catch {
      // ignore — user can retry
    } finally {
      setTemplateSaving(false);
    }
  }

  const scheduleValid = scheduledAt && new Date(scheduledAt) > new Date();
  const wordCountStats = useWordCount(body);

  return (
    <div className="max-w-3xl mx-auto">
      {/* Toast notification */}
      {templateToast && (
        <div className="fixed bottom-6 right-6 z-50 px-4 py-2.5 bg-gray-900 text-white text-sm rounded-lg shadow-lg animate-fade-in">
          Template saved
        </div>
      )}

      <div className="bg-white border border-gray-200 rounded-lg p-6 space-y-4">
        <div className="flex items-center justify-between gap-3">
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Post title…"
            className="flex-1 text-2xl font-bold border-none outline-none placeholder-gray-300"
          />
          <div className="flex items-center gap-2 shrink-0">
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
            {isLoggedIn && (
              <div className="relative" ref={templatePickerRef}>
                <button
                  type="button"
                  onClick={() => setShowTemplatePicker((v) => !v)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs border border-gray-200 rounded-md text-gray-500 hover:bg-gray-50 transition-colors"
                >
                  Load template <ChevronDown className="w-3 h-3" />
                </button>
                {showTemplatePicker && (
                  <div className="absolute right-0 top-full mt-1 z-20 min-w-[220px] bg-white border border-gray-200 rounded-lg shadow-lg py-1">
                    {templates.length === 0 ? (
                      <p className="px-4 py-3 text-xs text-gray-400 italic">No templates yet</p>
                    ) : (
                      templates.map((tpl) => (
                        <button
                          key={tpl.id}
                          type="button"
                          onClick={() => applyTemplate(tpl)}
                          className="w-full text-left px-4 py-2 hover:bg-gray-50 transition-colors"
                        >
                          <p className="text-sm font-medium text-gray-800 truncate">{tpl.name}</p>
                          {tpl.title && (
                            <p className="text-xs text-gray-400 truncate">{tpl.title}</p>
                          )}
                        </button>
                      ))
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        <TagInput
          value={tags}
          onChange={setTags}
          maxTags={5}
          placeholder="Add tags… (e.g. opencsirt, apiguard, nis2)"
        />
        {isLoggedIn && (
          <SeriesSelector value={seriesId} onChange={setSeriesId} />
        )}
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
              {scheduledAt && !scheduleValid && (
                <span className="text-xs text-red-500">Must be in the future</span>
              )}
            </div>
            <button
              type="button"
              onClick={() => { setShowSchedule(false); setScheduledAt(""); }}
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

        {/* Save as template inline form */}
        {isLoggedIn && showSaveTemplate && (
          <div className="flex items-center gap-2 p-3 bg-gray-50 border border-gray-200 rounded-lg">
            <input
              type="text"
              value={templateName}
              onChange={(e) => setTemplateName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleSaveTemplate();
                if (e.key === "Escape") { setShowSaveTemplate(false); setTemplateName(""); }
              }}
              placeholder="Template name"
              autoFocus
              className="flex-1 text-sm border border-gray-300 rounded-md px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            <button
              type="button"
              onClick={handleSaveTemplate}
              disabled={templateSaving || !templateName.trim()}
              className="px-3 py-1.5 text-sm bg-gray-800 text-white rounded-md hover:bg-gray-700 disabled:opacity-50 transition-colors"
            >
              {templateSaving ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              onClick={() => { setShowSaveTemplate(false); setTemplateName(""); }}
              className="px-3 py-1.5 text-sm border border-gray-200 rounded-md text-gray-500 hover:bg-gray-100 transition-colors"
            >
              Cancel
            </button>
          </div>
        )}

        <div className="flex gap-3 flex-wrap">
          <button
            onClick={() => handleSave("publish")}
            disabled={saving || !title.trim()}
            className="px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
          >
            {saving ? "Publishing…" : "Publish"}
          </button>
          {showSchedule ? (
            <button
              onClick={() => handleSave("schedule")}
              disabled={saving || !title.trim() || !scheduleValid}
              className="px-5 py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
            >
              {saving ? "Scheduling…" : "Schedule"}
            </button>
          ) : (
            <button
              type="button"
              onClick={() => setShowSchedule(true)}
              className="px-5 py-2 border border-indigo-300 text-indigo-600 text-sm rounded-lg hover:bg-indigo-50 transition-colors flex items-center gap-1.5"
            >
              <Calendar className="w-4 h-4" /> Schedule
            </button>
          )}
          <button
            onClick={() => handleSave("draft")}
            disabled={saving || !title.trim()}
            className="px-5 py-2 border border-gray-300 text-sm rounded-lg hover:bg-gray-50 disabled:opacity-50 transition-colors"
          >
            Save draft
          </button>
          {isLoggedIn && !showSaveTemplate && (
            <button
              type="button"
              onClick={() => {
                setTemplateName(title);
                setShowSaveTemplate(true);
              }}
              className="px-5 py-2 border border-gray-200 text-gray-500 text-sm rounded-lg hover:bg-gray-50 transition-colors"
            >
              Save as template
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
