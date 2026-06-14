import { useState } from "react";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/state/auth";

interface Props {
  commentId: string;
  initialCounts?: Record<string, number>;
  initialUserReactions?: Record<string, boolean>;
}

const EMOJIS: { kind: string; emoji: string }[] = [
  { kind: "heart", emoji: "❤️" },
  { kind: "unicorn", emoji: "🦄" },
  { kind: "fire", emoji: "🔥" },
];

export default function CommentReactions({ commentId, initialCounts = {}, initialUserReactions = {} }: Props) {
  const token = useAuthStore((s) => s.token);
  const [counts, setCounts] = useState<Record<string, number>>(initialCounts);
  const [userReactions, setUserReactions] = useState<Record<string, boolean>>(initialUserReactions);

  const toggle = async (kind: string) => {
    if (!token) return;
    try {
      const res = await apiClient.post(`/comments/${commentId}/reactions`, { kind });
      setCounts(res.data.counts);
      setUserReactions(res.data.user_reactions);
    } catch {}
  };

  return (
    <div className="flex gap-2 mt-1">
      {EMOJIS.map(({ kind, emoji }) => (
        <button
          key={kind}
          onClick={() => toggle(kind)}
          className={`flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border transition-colors ${
            userReactions[kind]
              ? "border-indigo-400 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-300"
              : "border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-gray-400"
          } ${!token ? "cursor-default" : "cursor-pointer"}`}
          disabled={!token}
        >
          <span>{emoji}</span>
          {(counts[kind] ?? 0) > 0 && <span>{counts[kind]}</span>}
        </button>
      ))}
    </div>
  );
}
