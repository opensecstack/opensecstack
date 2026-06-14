import { useState } from "react";

export const REACTIONS = [
  { kind: "like",      emoji: "👍", label: "Like" },
  { kind: "heart",     emoji: "❤️", label: "Love" },
  { kind: "fire",      emoji: "🔥", label: "Fire" },
  { kind: "insight",   emoji: "💡", label: "Insightful" },
  { kind: "celebrate", emoji: "🎉", label: "Celebrate" },
] as const;

interface ReactionBarProps {
  postId: number | string;
  counts: Record<string, number>;
  userReactions: string[];
  onReact: (kind: string) => void;
  onUnreact: (kind: string) => void;
}

export default function ReactionBar({
  counts,
  userReactions,
  onReact,
  onUnreact,
}: ReactionBarProps) {
  // Track which button just changed so we can animate it briefly.
  const [animating, setAnimating] = useState<string | null>(null);

  function handleClick(kind: string) {
    const active = userReactions.includes(kind);
    setAnimating(kind);
    setTimeout(() => setAnimating(null), 300);
    if (active) {
      onUnreact(kind);
    } else {
      onReact(kind);
    }
  }

  return (
    <div className="flex flex-wrap gap-1.5" role="group" aria-label="Post reactions">
      {REACTIONS.map(({ kind, emoji, label }) => {
        const active = userReactions.includes(kind);
        const count = counts[kind] ?? 0;
        const isAnimating = animating === kind;

        return (
          <div key={kind} className="relative group">
            {/* Tooltip */}
            <span
              className="pointer-events-none absolute -top-8 left-1/2 -translate-x-1/2 whitespace-nowrap rounded bg-gray-800 px-1.5 py-0.5 text-[11px] text-white opacity-0 transition-opacity group-hover:opacity-100 dark:bg-gray-700 z-10"
              role="tooltip"
            >
              {label}
            </span>

            <button
              type="button"
              onClick={() => handleClick(kind)}
              aria-label={`${label}${count > 0 ? ` (${count})` : ""}`}
              aria-pressed={active}
              className={[
                "flex items-center gap-1 rounded-full border px-2.5 py-1 transition-all duration-150 select-none",
                active
                  ? "border-indigo-400 bg-indigo-50 ring-1 ring-indigo-300 dark:border-indigo-500 dark:bg-indigo-900/30 dark:ring-indigo-600"
                  : "border-gray-200 bg-white hover:border-indigo-300 hover:bg-indigo-50/40 dark:border-gray-700 dark:bg-gray-900 dark:hover:border-indigo-700 dark:hover:bg-indigo-900/20",
              ].join(" ")}
            >
              <span
                className={[
                  "text-lg leading-none transition-opacity duration-150",
                  isAnimating ? "opacity-60" : "opacity-100",
                ].join(" ")}
              >
                {emoji}
              </span>
              {count > 0 && (
                <span
                  className={[
                    "text-xs font-medium tabular-nums transition-opacity duration-150",
                    active
                      ? "text-indigo-600 dark:text-indigo-400"
                      : "text-gray-500 dark:text-gray-400",
                    isAnimating ? "opacity-60" : "opacity-100",
                  ].join(" ")}
                >
                  {count}
                </span>
              )}
            </button>
          </div>
        );
      })}
    </div>
  );
}
