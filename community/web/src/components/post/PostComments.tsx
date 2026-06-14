import { useState } from "react";
import { useInfiniteQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { listComments, createComment, updateComment } from "@/api/comments";
import { addCommentReaction, removeCommentReaction } from "@/api/reactions";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";
import MentionTextarea from "@/components/MentionTextarea";
import CommentReactions from "@/components/CommentReactions";
import { Heart, Pencil } from "lucide-react";

type InfiniteCommentsData = import("@tanstack/react-query").InfiniteData<
  import("@/api/comments").CommentListResponse
>;

function renderWithMentions(text: string): React.ReactNode {
  const parts = text.split(/(@[a-zA-Z0-9_]+)/g);
  return parts.map((part, i) => {
    if (/^@[a-zA-Z0-9_]+$/.test(part)) {
      const username = part.slice(1);
      return (
        <Link key={i} to={`/users/${username}`} className="text-brand hover:underline">
          {part}
        </Link>
      );
    }
    return part;
  });
}

interface PostCommentsProps {
  postId: string;
  locked: boolean;
}

const COMMENTS_PER_PAGE = 20;

export default function PostComments({ postId, locked }: PostCommentsProps) {
  const { token, username: authUsername } = useAuthStore();
  const navigate = useNavigate();
  const qc = useQueryClient();

  const [comment, setComment] = useState("");
  const [commentSort, setCommentSort] = useState<"newest" | "oldest" | "top">("newest");
  const [editingCommentId, setEditingCommentId] = useState<string | null>(null);
  const [editBody, setEditBody] = useState("");
  const [replyingTo, setReplyingTo] = useState<string | null>(null);
  const [replyText, setReplyText] = useState("");

  const {
    data: commentsData,
    fetchNextPage,
    isFetchingNextPage,
  } = useInfiniteQuery({
    queryKey: ["comments", postId, commentSort],
    queryFn: ({ pageParam = 1 }) =>
      listComments(postId, commentSort, pageParam as number, COMMENTS_PER_PAGE),
    getNextPageParam: (_lastPage, pages) =>
      pages.flatMap((p) => p.comments).length < _lastPage.total
        ? pages.length + 1
        : undefined,
    initialPageParam: 1,
    enabled: !!postId,
  });

  const allCommentPages = commentsData?.pages ?? [];
  const allComments = allCommentPages.flatMap((p) => p.comments);
  const commentTotal = allCommentPages[0]?.total ?? 0;
  const commentHasMore =
    allCommentPages.length > 0 ? allComments.length < commentTotal : false;

  const topLevelComments = allComments.filter((c) => c.parent_id === null);
  const repliesFor = (id: string) => allComments.filter((c) => c.parent_id === id);

  function patchCommentReaction(
    commentId: string,
    reacted: boolean,
    delta: number,
  ) {
    qc.setQueryData<InfiniteCommentsData>(["comments", postId, commentSort], (old) => {
      if (!old) return old;
      return {
        ...old,
        pages: old.pages.map((page) => ({
          ...page,
          comments: page.comments.map((c) =>
            c.id === commentId
              ? { ...c, viewer_reacted: reacted, reaction_count: c.reaction_count + delta }
              : c,
          ),
        })),
      };
    });
  }

  async function handleCommentReact(commentId: string, currentlyReacted: boolean) {
    patchCommentReaction(commentId, !currentlyReacted, currentlyReacted ? -1 : 1);
    try {
      if (currentlyReacted) {
        await removeCommentReaction(commentId);
      } else {
        await addCommentReaction(commentId);
      }
    } catch {
      patchCommentReaction(commentId, currentlyReacted, currentlyReacted ? 1 : -1);
    }
  }

  async function submitComment(e: React.FormEvent) {
    e.preventDefault();
    if (!comment.trim()) return;
    try {
      await createComment(postId, comment.trim());
      setComment("");
      qc.invalidateQueries({ queryKey: ["comments", postId] });
    } catch {
      // silently ignore
    }
  }

  async function submitReply(parentId: string) {
    if (!replyText.trim()) return;
    try {
      await createComment(postId, replyText.trim(), parentId);
      setReplyText("");
      setReplyingTo(null);
      qc.invalidateQueries({ queryKey: ["comments", postId] });
    } catch {
      // silently ignore
    }
  }

  const saveCommentEdit = useMutation({
    mutationFn: ({ id, body }: { id: string; body: string }) => updateComment(id, body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["comments", postId] });
      setEditingCommentId(null);
    },
  });

  return (
    <section data-print="hide" className="mt-8">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Comments</h2>

      {token && !locked && (
        <form onSubmit={submitComment} className="mb-6">
          <MentionTextarea
            value={comment}
            onChange={setComment}
            placeholder="Add a comment..."
            rows={3}
            className="w-full border border-gray-300 dark:border-gray-700 rounded-lg p-3 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
          />
          <button
            type="submit"
            className="mt-2 px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
          >
            Post comment
          </button>
        </form>
      )}

      {!token && (
        <p data-print="hide" className="mb-4 text-sm text-gray-400 dark:text-gray-500">
          <Link to="/login" className="text-brand hover:underline">Log in</Link> to react or leave a comment.
        </p>
      )}

      {/* Sort controls */}
      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <span className="text-sm text-gray-500 dark:text-gray-400">Sort:</span>
        {(["newest", "oldest", "top"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setCommentSort(s)}
            className={`text-sm px-2 py-0.5 rounded ${
              commentSort === s
                ? "bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700 dark:text-indigo-300"
                : "text-gray-500 dark:text-gray-400 hover:text-gray-700"
            }`}
          >
            {s.charAt(0).toUpperCase() + s.slice(1)}
          </button>
        ))}
        {commentTotal > 0 && (
          <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">
            Showing {allComments.length} of {commentTotal} comment{commentTotal !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      <div className="space-y-4">
        {topLevelComments.map((c) => {
          const replies = repliesFor(c.id);
          return (
            <div key={c.id}>
              {/* Top-level comment card */}
              <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-7 h-7 rounded-full bg-brand/20 flex items-center justify-center text-brand text-xs font-bold">
                    {c.author_display_name?.[0] ?? c.author_username[0]}
                  </div>
                  <Link to={`/users/${c.author_username}`} className="text-sm font-medium hover:text-brand">
                    {c.author_display_name || c.author_username}
                  </Link>
                  <span className="text-xs text-gray-400 dark:text-gray-500 ml-auto">{timeAgo(c.created_at)}</span>
                  {c.author_username === authUsername && editingCommentId !== c.id && (
                    <button
                      onClick={() => { setEditingCommentId(c.id); setEditBody(c.body); }}
                      className="flex items-center gap-1 text-xs text-gray-400 dark:text-gray-500 hover:text-brand transition-colors ml-1"
                      title="Edit comment"
                    >
                      <Pencil className="w-3 h-3" /> Edit
                    </button>
                  )}
                </div>

                {editingCommentId === c.id ? (
                  <div className="mt-1">
                    <textarea
                      value={editBody}
                      onChange={(e) => setEditBody(e.target.value)}
                      className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-brand/40 resize-none"
                      rows={3}
                    />
                    <div className="flex gap-2 mt-2">
                      <button
                        onClick={() => {
                          if (!editBody.trim()) return;
                          saveCommentEdit.mutate({ id: c.id, body: editBody.trim() });
                        }}
                        className="px-3 py-1.5 bg-brand text-white text-xs rounded-lg hover:bg-brand-dark transition-colors"
                      >
                        Save
                      </button>
                      <button
                        onClick={() => setEditingCommentId(null)}
                        className="px-3 py-1.5 border border-gray-300 dark:border-gray-700 text-gray-500 dark:text-gray-400 text-xs rounded-lg hover:border-gray-400 dark:hover:border-gray-600 transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {renderWithMentions(c.body)}
                    </p>
                    <CommentReactions commentId={c.id} />
                  </>
                )}

                {editingCommentId !== c.id && (
                  <button
                    onClick={() => {
                      if (!token) { navigate("/login"); return; }
                      handleCommentReact(c.id, c.viewer_reacted);
                    }}
                    disabled={!token}
                    className={`flex items-center gap-1 text-xs mt-2 transition-colors ${
                      c.viewer_reacted ? "text-rose-500" : "text-gray-400 hover:text-rose-400"
                    }`}
                    title={!token ? "Log in to react" : undefined}
                  >
                    <Heart className="w-3.5 h-3.5" fill={c.viewer_reacted ? "currentColor" : "none"} />
                    {c.reaction_count > 0 && <span>{c.reaction_count}</span>}
                  </button>
                )}

                {token && !locked && editingCommentId !== c.id && (
                  <div className="mt-2">
                    <button
                      onClick={() => {
                        if (replyingTo === c.id) {
                          setReplyingTo(null);
                          setReplyText("");
                        } else {
                          setReplyingTo(c.id);
                          setReplyText("");
                        }
                      }}
                      className="text-xs text-gray-400 dark:text-gray-500 hover:text-brand transition-colors"
                    >
                      Reply
                    </button>
                  </div>
                )}
              </div>

              {/* Inline reply form */}
              {replyingTo === c.id && (
                <div className="ml-8 mt-2 pl-4 border-l-2 border-gray-100 dark:border-gray-800">
                  <textarea
                    value={replyText}
                    onChange={(e) => setReplyText(e.target.value)}
                    placeholder="Write a reply..."
                    rows={2}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40 resize-none"
                  />
                  <div className="flex gap-2 mt-1.5">
                    <button
                      onClick={() => submitReply(c.id)}
                      className="px-3 py-1.5 bg-brand text-white text-xs rounded-lg hover:bg-brand-dark transition-colors"
                    >
                      Post reply
                    </button>
                    <button
                      onClick={() => { setReplyingTo(null); setReplyText(""); }}
                      className="px-3 py-1.5 border border-gray-300 dark:border-gray-700 text-gray-500 dark:text-gray-400 text-xs rounded-lg hover:border-gray-400 dark:hover:border-gray-600 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Replies */}
              {replies.length > 0 && (
                <div className="ml-8 mt-2 space-y-2 border-l-2 border-gray-100 dark:border-gray-800 pl-4">
                  {replies.map((r) => (
                    <div key={r.id} className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-3">
                      <div className="flex items-center gap-2 mb-1.5">
                        <div className="w-6 h-6 rounded-full bg-brand/20 flex items-center justify-center text-brand text-xs font-bold">
                          {r.author_display_name?.[0] ?? r.author_username[0]}
                        </div>
                        <Link to={`/users/${r.author_username}`} className="text-xs font-medium hover:text-brand">
                          {r.author_display_name || r.author_username}
                        </Link>
                        <span className="text-xs text-gray-400 dark:text-gray-500 ml-auto">{timeAgo(r.created_at)}</span>
                        {r.author_username === authUsername && editingCommentId !== r.id && (
                          <button
                            onClick={() => { setEditingCommentId(r.id); setEditBody(r.body); }}
                            className="flex items-center gap-1 text-xs text-gray-400 dark:text-gray-500 hover:text-brand transition-colors ml-1"
                            title="Edit reply"
                          >
                            <Pencil className="w-3 h-3" /> Edit
                          </button>
                        )}
                      </div>

                      {editingCommentId === r.id ? (
                        <div className="mt-1">
                          <textarea
                            value={editBody}
                            onChange={(e) => setEditBody(e.target.value)}
                            className="w-full px-3 py-2 text-xs border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-brand/40 resize-none"
                            rows={2}
                          />
                          <div className="flex gap-2 mt-2">
                            <button
                              onClick={() => {
                                if (!editBody.trim()) return;
                                saveCommentEdit.mutate({ id: r.id, body: editBody.trim() });
                              }}
                              className="px-3 py-1 bg-brand text-white text-xs rounded-lg hover:bg-brand-dark transition-colors"
                            >
                              Save
                            </button>
                            <button
                              onClick={() => setEditingCommentId(null)}
                              className="px-3 py-1 border border-gray-300 dark:border-gray-700 text-gray-500 dark:text-gray-400 text-xs rounded-lg hover:border-gray-400 dark:hover:border-gray-600 transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <>
                          <p className="text-xs text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                            {renderWithMentions(r.body)}
                          </p>
                          <CommentReactions commentId={r.id} />
                        </>
                      )}

                      {editingCommentId !== r.id && (
                        <button
                          onClick={() => {
                            if (!token) { navigate("/login"); return; }
                            handleCommentReact(r.id, r.viewer_reacted);
                          }}
                          disabled={!token}
                          className={`flex items-center gap-1 text-xs mt-2 transition-colors ${
                            r.viewer_reacted ? "text-rose-500" : "text-gray-400 hover:text-rose-400"
                          }`}
                          title={!token ? "Log in to react" : undefined}
                        >
                          <Heart className="w-3.5 h-3.5" fill={r.viewer_reacted ? "currentColor" : "none"} />
                          {r.reaction_count > 0 && <span>{r.reaction_count}</span>}
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {commentHasMore && (
        <div className="mt-6 flex justify-center">
          <button
            onClick={() => fetchNextPage()}
            disabled={isFetchingNextPage}
            className="px-5 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg text-gray-600 dark:text-gray-400 hover:border-brand hover:text-brand transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isFetchingNextPage ? "Loading…" : "Load more comments"}
          </button>
        </div>
      )}
    </section>
  );
}
