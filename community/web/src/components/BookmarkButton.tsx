import { useQuery, useQueryClient } from "@tanstack/react-query";
import { bookmarkPost, unbookmarkPost, getBookmarkStatus } from "@/api/bookmarks";
import { useAuthStore } from "@/state/auth";

interface Props {
  postId: string;
}

export default function BookmarkButton({ postId }: Props) {
  const { token } = useAuthStore();
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["bookmark-status", postId],
    queryFn: () => getBookmarkStatus(postId),
    enabled: !!token,
  });

  if (!token) return null;

  async function toggle() {
    if (data?.bookmarked) {
      await unbookmarkPost(postId);
    } else {
      await bookmarkPost(postId);
    }
    qc.invalidateQueries({ queryKey: ["bookmark-status", postId] });
    qc.invalidateQueries({ queryKey: ["bookmarks"] });
  }

  return (
    <button
      onClick={toggle}
      disabled={isLoading}
      className={`flex items-center gap-1.5 px-4 py-2 border rounded-lg text-sm transition-colors disabled:opacity-50 ${
        data?.bookmarked
          ? "bg-brand/10 border-brand/30 text-brand"
          : "bg-white border-gray-200 text-gray-500 hover:border-brand/40"
      }`}
      aria-label={data?.bookmarked ? "Remove bookmark" : "Bookmark"}
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        className="w-4 h-4"
        viewBox="0 0 24 24"
        fill={data?.bookmarked ? "currentColor" : "none"}
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
      </svg>
      {data?.bookmarked ? "Saved" : "Save"}
    </button>
  );
}
