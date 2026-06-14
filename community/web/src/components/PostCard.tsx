import { useState } from "react";
import { Link } from "react-router-dom";
import { MessageCircle, Eye } from "lucide-react";
import { timeAgo } from "@/lib/format";
import { readingTime } from "@/lib/readingTime";
import type { Post } from "@/api/posts";
import TagBadge from "./TagBadge";
import { useMutedUsers } from "@/hooks/useMutedUsers";
import ShareButton from "./ShareButton";

interface Props {
  post: Post;
  linkTo?: string;
}

export default function PostCard({ post, linkTo }: Props) {
  const mutedUsers = useMutedUsers();
  const [showAnyway, setShowAnyway] = useState(false);

  if (mutedUsers.has(post.author_username) && !showAnyway) {
    return (
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4 flex items-center justify-between text-sm text-gray-400 dark:text-gray-500">
        <span>Post from a muted user</span>
        <button
          onClick={() => setShowAnyway(true)}
          className="text-brand hover:underline text-xs"
        >
          Show anyway
        </button>
      </div>
    );
  }

  return (
    <article className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-5 hover:border-brand/40 transition-colors">
      <div className="flex items-center gap-2 mb-3">
        <div className="w-8 h-8 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-sm">
          {post.author_display_name?.[0] ?? post.author_username[0]}
        </div>
        <div>
          <Link to={`/users/${post.author_username}`} className="text-sm font-medium hover:text-brand">
            {post.author_display_name || post.author_username}
          </Link>
          {post.author_platform_badge && (
            <span className="ml-2 text-xs bg-indigo-50 text-brand px-1.5 py-0.5 rounded">
              {post.author_platform_badge}
            </span>
          )}
          <p className="text-xs text-gray-400 dark:text-gray-500">
            {timeAgo(post.created_at)}
            {post.edited_at && <span className="ml-1">· Edited</span>}
          </p>
        </div>
      </div>

      {post.cover_image_url && (
        <img src={post.cover_image_url} alt="" className="w-full h-40 object-cover rounded-md mb-3" />
      )}

      {post.pinned && (
        <span className="text-xs text-gray-500 dark:text-gray-400 flex items-center gap-1 mb-1">
          📌 <span>Pinned</span>
        </span>
      )}
      <Link to={linkTo ?? `/posts/${post.slug}`}>
        <h2 className="text-lg font-bold text-gray-900 dark:text-gray-100 hover:text-brand mb-2 line-clamp-2">{post.title}</h2>
      </Link>
      {post.sensitive && (
        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400 mb-2">
          Sensitive
        </span>
      )}

      <div className="flex flex-wrap gap-1.5 mb-4">
        {post.tags.map((t) => (
          <TagBadge key={t} name={t} />
        ))}
      </div>

      <div className="flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
        <span className="flex items-center gap-1.5">
          {post.reaction_count > 0 ? (
            <>
              <span>❤️</span>
              <span>🦄</span>
              <span>🔥</span>
              <span>{post.reaction_count}</span>
            </>
          ) : (
            <span className="opacity-40">❤️ 🦄 🔥</span>
          )}
        </span>
        <span className="flex items-center gap-1">
          <MessageCircle className="w-4 h-4" /> {post.comment_count}
        </span>
        {post.views !== undefined && (
          <span className="flex items-center gap-1 text-gray-400 dark:text-gray-500">
            <Eye className="w-4 h-4" /> {post.views} views
          </span>
        )}
        <span className="text-xs text-gray-400 dark:text-gray-500">
          {post.reading_time_minutes ?? readingTime(post.body ?? "")} min read
        </span>
        <span className="ml-auto">
          <ShareButton
            title={post.title}
            url={window.location.origin + "/posts/" + post.slug}
            compact
          />
        </span>
      </div>
    </article>
  );
}
