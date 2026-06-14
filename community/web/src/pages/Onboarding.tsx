import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { listTags, followTag } from "@/api/tags";
import { listPosts } from "@/api/posts";
import { updateMe } from "@/api/users";
import { followUser } from "@/api/follows";
import { uploadImage } from "@/api/upload";
import { useAuthStore } from "@/state/auth";
import type { Post } from "@/api/posts";

const ONBOARDING_KEY = "onboarding_completed";

// ──────────────────────────────────────────
// Step indicator dots
// ──────────────────────────────────────────
function StepIndicator({ step }: { step: number }) {
  return (
    <div className="flex items-center justify-center gap-2 mb-6">
      {[1, 2, 3].map((dot) => (
        <span
          key={dot}
          className={`block w-2.5 h-2.5 rounded-full transition-colors ${
            dot <= step
              ? "bg-indigo-600"
              : "bg-gray-200 dark:bg-gray-700"
          }`}
        />
      ))}
    </div>
  );
}

function StepLabel({ step }: { step: number }) {
  return (
    <p className="text-sm text-gray-400 dark:text-gray-500 mb-2 text-center">
      Step {step} of 3
    </p>
  );
}

// ──────────────────────────────────────────
// Avatar upload widget
// ──────────────────────────────────────────
function AvatarUpload({
  avatarUrl,
  setAvatarUrl,
}: {
  avatarUrl: string;
  setAvatarUrl: (url: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState("");

  async function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    setUploadError("");
    try {
      const url = await uploadImage(file);
      setAvatarUrl(url);
    } catch {
      setUploadError("Upload failed. Try again.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
        Avatar (optional)
      </label>
      <div className="flex items-center gap-4">
        {avatarUrl ? (
          <img
            src={avatarUrl}
            alt="Avatar preview"
            className="w-14 h-14 rounded-full object-cover border border-gray-200 dark:border-gray-700 shrink-0"
          />
        ) : (
          <div className="w-14 h-14 rounded-full bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 flex items-center justify-center shrink-0">
            <svg
              className="w-6 h-6 text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"
              />
            </svg>
          </div>
        )}
        <div className="flex flex-col gap-1">
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            disabled={uploading}
            className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors disabled:opacity-50"
          >
            {uploading ? "Uploading…" : avatarUrl ? "Change photo" : "Upload photo"}
          </button>
          {avatarUrl && (
            <button
              type="button"
              onClick={() => setAvatarUrl("")}
              className="text-xs text-gray-400 hover:text-gray-500 text-left"
            >
              Remove
            </button>
          )}
        </div>
        <input
          ref={inputRef}
          type="file"
          accept="image/*"
          className="hidden"
          onChange={handleFile}
        />
      </div>
      {uploadError && (
        <p className="mt-1 text-xs text-red-500">{uploadError}</p>
      )}
    </div>
  );
}

// ──────────────────────────────────────────
// Step 1 — Profile setup
// ──────────────────────────────────────────
function StepProfile({
  displayName,
  setDisplayName,
  bio,
  setBio,
  avatarUrl,
  setAvatarUrl,
  onNext,
  onSkip,
}: {
  displayName: string;
  setDisplayName: (v: string) => void;
  bio: string;
  setBio: (v: string) => void;
  avatarUrl: string;
  setAvatarUrl: (v: string) => void;
  onNext: () => void;
  onSkip: () => void;
}) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function handleNext() {
    setSaving(true);
    setError("");
    try {
      await updateMe({
        display_name: displayName || undefined,
        bio: bio || undefined,
        avatar_url: avatarUrl || undefined,
      });
      onNext();
    } catch {
      setError("Failed to save profile. Please try again.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between mb-1">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            Welcome to SIN
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 mb-6">
            Let's set up your profile so the community knows who you are.
          </p>
        </div>
        <button
          onClick={onSkip}
          className="text-sm text-gray-400 hover:text-gray-500 shrink-0 ml-4"
        >
          Skip
        </button>
      </div>

      <div className="space-y-5 mb-6">
        <AvatarUpload avatarUrl={avatarUrl} setAvatarUrl={setAvatarUrl} />

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Display name
          </label>
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Your name"
            className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-400/40"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Bio{" "}
            <span className="text-gray-400 font-normal">
              (optional, {160 - bio.length} chars left)
            </span>
          </label>
          <textarea
            value={bio}
            onChange={(e) => setBio(e.target.value.slice(0, 160))}
            placeholder="A short bio about yourself…"
            rows={3}
            className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-400/40 resize-none"
          />
        </div>
      </div>

      {error && <p className="text-sm text-red-500 mb-3">{error}</p>}

      <button
        onClick={handleNext}
        disabled={saving}
        className="w-full py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
      >
        {saving ? "Saving…" : "Next →"}
      </button>
    </div>
  );
}

// ──────────────────────────────────────────
// Step 2 — Pick interests (follow tags)
// ──────────────────────────────────────────
function StepInterests({
  selectedSlugs,
  setSelectedSlugs,
  onNext,
  onSkip,
}: {
  selectedSlugs: Set<string>;
  setSelectedSlugs: (s: Set<string>) => void;
  onNext: () => void;
  onSkip: () => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["tags"],
    queryFn: () => listTags(50),
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  function toggle(slug: string) {
    const next = new Set(selectedSlugs);
    if (next.has(slug)) {
      next.delete(slug);
    } else {
      next.add(slug);
    }
    setSelectedSlugs(next);
  }

  async function handleNext() {
    if (selectedSlugs.size === 0) {
      onNext();
      return;
    }
    setSaving(true);
    setError("");
    try {
      await Promise.all([...selectedSlugs].map((slug) => followTag(slug)));
      onNext();
    } catch {
      setError("Failed to follow some tags. You can manage them from your profile later.");
      onNext();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between mb-1">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
          Pick your interests
        </h1>
        <button
          onClick={onSkip}
          className="text-sm text-gray-400 hover:text-gray-500 shrink-0 ml-4 mt-1"
        >
          Skip
        </button>
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
        Follow tags to personalise your feed. Select up to 5.
      </p>

      {isLoading ? (
        <div className="flex flex-wrap gap-2 mb-8">
          {Array.from({ length: 12 }).map((_, i) => (
            <span
              key={i}
              className="h-8 w-20 rounded-full bg-gray-100 dark:bg-gray-800 animate-pulse"
            />
          ))}
        </div>
      ) : (
        <div className="flex flex-wrap gap-2 mb-8">
          {(data?.tags ?? []).map((tag) => {
            const selected = selectedSlugs.has(tag.slug);
            const maxReached = selectedSlugs.size >= 5 && !selected;
            return (
              <button
                key={tag.id}
                onClick={() => !maxReached && toggle(tag.slug)}
                disabled={maxReached}
                className={`px-3 py-1.5 rounded-full text-sm border transition-colors ${
                  selected
                    ? "bg-indigo-600 text-white border-indigo-600"
                    : maxReached
                    ? "bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 text-gray-400 cursor-not-allowed opacity-50"
                    : "bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-indigo-400/60"
                }`}
              >
                {tag.name}
              </button>
            );
          })}
        </div>
      )}

      {selectedSlugs.size > 0 && (
        <p className="text-xs text-gray-400 dark:text-gray-500 mb-3">
          {selectedSlugs.size} / 5 selected
        </p>
      )}

      {error && <p className="text-sm text-red-500 mb-3">{error}</p>}

      <button
        onClick={handleNext}
        disabled={saving}
        className="w-full py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
      >
        {saving ? "Saving…" : "Next →"}
      </button>
    </div>
  );
}

// ──────────────────────────────────────────
// Step 3 — Follow people
// ──────────────────────────────────────────

interface SuggestedUser {
  username: string;
  display_name: string;
  avatar_url: string | null;
}

function extractUniqueAuthors(posts: Post[]): SuggestedUser[] {
  const seen = new Set<string>();
  const authors: SuggestedUser[] = [];
  for (const post of posts) {
    if (!seen.has(post.author_username)) {
      seen.add(post.author_username);
      authors.push({
        username: post.author_username,
        display_name: post.author_display_name,
        avatar_url: post.author_avatar_url,
      });
    }
    if (authors.length >= 6) break;
  }
  return authors;
}

function UserCard({
  user,
  currentUsername,
}: {
  user: SuggestedUser;
  currentUsername: string | null;
}) {
  const [followed, setFollowed] = useState(false);
  const [loading, setLoading] = useState(false);

  // Don't show the logged-in user in the list
  if (user.username === currentUsername) return null;

  async function handleFollow() {
    setLoading(true);
    try {
      await followUser(user.username);
      setFollowed(true);
    } catch {
      // silently ignore — non-critical
    } finally {
      setLoading(false);
    }
  }

  const initials = (user.display_name || user.username)
    .split(" ")
    .slice(0, 2)
    .map((w) => w[0])
    .join("")
    .toUpperCase();

  return (
    <div className="flex items-center gap-3 py-3 border-b border-gray-100 dark:border-gray-800 last:border-0">
      {user.avatar_url ? (
        <img
          src={user.avatar_url}
          alt={user.display_name}
          className="w-10 h-10 rounded-full object-cover shrink-0"
        />
      ) : (
        <div className="w-10 h-10 rounded-full bg-indigo-100 dark:bg-indigo-900 flex items-center justify-center shrink-0 text-indigo-600 dark:text-indigo-300 text-sm font-semibold">
          {initials}
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
          {user.display_name || user.username}
        </p>
        <p className="text-xs text-gray-400 truncate">@{user.username}</p>
      </div>
      <button
        onClick={handleFollow}
        disabled={followed || loading}
        className={`shrink-0 px-3 py-1 text-xs rounded-full border transition-colors ${
          followed
            ? "border-indigo-600 text-indigo-600 bg-indigo-50 dark:bg-indigo-900/30 cursor-default"
            : "border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:border-indigo-400 hover:text-indigo-600 disabled:opacity-50"
        }`}
      >
        {loading ? "…" : followed ? "Following" : "Follow"}
      </button>
    </div>
  );
}

function StepPeople({
  currentUsername,
  onFinish,
  onSkip,
}: {
  currentUsername: string | null;
  onFinish: () => void;
  onSkip: () => void;
}) {
  const { data, isLoading } = useQuery({
    queryKey: ["onboarding-top-posts"],
    queryFn: () => listPosts(12, 0, "top"),
  });

  const suggested = data ? extractUniqueAuthors(data.posts) : [];
  // Filter out the current user
  const filtered = suggested.filter((u) => u.username !== currentUsername).slice(0, 6);

  return (
    <div>
      <div className="flex items-start justify-between mb-1">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
          Follow some people
        </h1>
        <button
          onClick={onSkip}
          className="text-sm text-gray-400 hover:text-gray-500 shrink-0 ml-4 mt-1"
        >
          Skip
        </button>
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
        Top contributors on SIN. Follow anyone whose work interests you.
      </p>

      {isLoading ? (
        <div className="space-y-3 mb-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 py-3">
              <div className="w-10 h-10 rounded-full bg-gray-100 dark:bg-gray-800 animate-pulse shrink-0" />
              <div className="flex-1 space-y-1.5">
                <div className="h-3 bg-gray-100 dark:bg-gray-800 rounded animate-pulse w-32" />
                <div className="h-2.5 bg-gray-100 dark:bg-gray-800 rounded animate-pulse w-20" />
              </div>
              <div className="h-6 w-16 bg-gray-100 dark:bg-gray-800 rounded-full animate-pulse" />
            </div>
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-gray-400 dark:text-gray-500 mb-6">
          No suggestions available yet — check back once the community grows!
        </p>
      ) : (
        <div className="mb-6">
          {filtered.map((user) => (
            <UserCard key={user.username} user={user} currentUsername={currentUsername} />
          ))}
        </div>
      )}

      <button
        onClick={onFinish}
        className="w-full py-2 bg-indigo-600 text-white text-sm rounded-lg hover:bg-indigo-700 transition-colors"
      >
        Go to my feed →
      </button>
    </div>
  );
}

// ──────────────────────────────────────────
// Main wizard
// ──────────────────────────────────────────
export default function Onboarding() {
  const navigate = useNavigate();
  const { token, username } = useAuthStore();

  const [step, setStep] = useState(1);

  // Step 1 state
  const [displayName, setDisplayName] = useState(username ?? "");
  const [bio, setBio] = useState("");
  const [avatarUrl, setAvatarUrl] = useState("");

  // Step 2 state
  const [selectedSlugs, setSelectedSlugs] = useState<Set<string>>(new Set());

  // Guard: not logged in
  useEffect(() => {
    if (!token) {
      navigate("/login", { replace: true });
    }
  }, [token, navigate]);

  // Guard: already completed onboarding
  useEffect(() => {
    if (localStorage.getItem(ONBOARDING_KEY) === "true") {
      navigate("/", { replace: true });
    }
  }, [navigate]);

  function finish() {
    localStorage.setItem(ONBOARDING_KEY, "true");
    navigate("/");
  }

  if (!token) return null;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex items-center justify-center px-4 py-12">
      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm p-8 w-full max-w-lg">
        <StepIndicator step={step} />
        <StepLabel step={step} />

        {step === 1 && (
          <StepProfile
            displayName={displayName}
            setDisplayName={setDisplayName}
            bio={bio}
            setBio={setBio}
            avatarUrl={avatarUrl}
            setAvatarUrl={setAvatarUrl}
            onNext={() => setStep(2)}
            onSkip={() => setStep(2)}
          />
        )}

        {step === 2 && (
          <StepInterests
            selectedSlugs={selectedSlugs}
            setSelectedSlugs={setSelectedSlugs}
            onNext={() => setStep(3)}
            onSkip={() => setStep(3)}
          />
        )}

        {step === 3 && (
          <StepPeople
            currentUsername={username}
            onFinish={finish}
            onSkip={finish}
          />
        )}

        {step > 1 && (
          <button
            onClick={() => setStep((s) => s - 1)}
            className="mt-4 w-full py-1.5 text-sm text-gray-400 dark:text-gray-500 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
          >
            ← Back
          </button>
        )}
      </div>
    </div>
  );
}
