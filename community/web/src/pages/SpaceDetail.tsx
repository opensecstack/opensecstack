import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, Link, useSearchParams } from "react-router-dom";
import {
  getSpace, createChannel, deleteChannel, joinSpace, leaveSpace, createSpaceInvite,
  getSpaceUnreadCounts, markChannelRead,
  type Channel,
} from "@/api/spaces";
import {
  listChannelMessages, sendChannelMessage,
  type ChannelMessage,
} from "@/api/channels";
import { useAuthStore } from "@/state/auth";
import { useState, useEffect, useRef, useCallback } from "react";
import Spinner from "@/components/Spinner";
import MessageBubble from "@/components/MessageBubble";
import MessageInput from "@/components/MessageInput";
import { useMutation } from "@tanstack/react-query";
import { Hash, Lock, Plus, Settings, LogOut, Link2, Megaphone, ChevronUp, Trash2 } from "lucide-react";

// --- helpers ----------------------------------------------------------------

/** Deduplicate messages by id, preserving order. */
function dedupMessages(msgs: ChannelMessage[]): ChannelMessage[] {
  const seen = new Set<string>();
  return msgs.filter((m) => {
    if (seen.has(m.id)) return false;
    seen.add(m.id);
    return true;
  });
}

// ---------------------------------------------------------------------------

export default function SpaceDetail() {
  const { slug } = useParams<{ slug: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const { token, username } = useAuthStore();
  const qc = useQueryClient();

  const activeChannel = searchParams.get("channel") ?? "general";

  // ── Space data ─────────────────────────────────────────────────────────────
  const { data, isLoading, error } = useQuery({
    queryKey: ["space", slug],
    queryFn: () => getSpace(slug!),
  });

  // ── Unread counts ──────────────────────────────────────────────────────────
  const { data: unreadCounts } = useQuery({
    queryKey: ["channel-unread", slug],
    queryFn: () => getSpaceUnreadCounts(slug!),
    enabled: !!data && !!token,
    refetchInterval: 30_000,
  });

  // Mark channel as read when switching to it
  useEffect(() => {
    if (!slug || !token) return;
    markChannelRead(slug, activeChannel).catch(() => {});
    qc.invalidateQueries({ queryKey: ["channel-unread", slug] });
  }, [activeChannel, slug, token]);

  // ── Messages ───────────────────────────────────────────────────────────────
  const { data: messagesData, isLoading: messagesLoading } = useQuery({
    queryKey: ["channel-messages", slug, activeChannel],
    queryFn: () => listChannelMessages(slug!, activeChannel),
    enabled: !!data,
  });

  const [messages, setMessages] = useState<ChannelMessage[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  // Seed local messages from query result whenever the channel changes
  useEffect(() => {
    if (messagesData) {
      setMessages(messagesData.messages);
      setHasMore(messagesData.has_more);
    }
  }, [messagesData]);

  // Reset local messages when switching channels
  useEffect(() => {
    setMessages([]);
    setHasMore(false);
  }, [activeChannel]);

  // ── Scroll management ──────────────────────────────────────────────────────
  const scrollRef = useRef<HTMLDivElement>(null);

  /**
   * The messages list uses flex-col-reverse so the DOM order is newest-first.
   * "Near bottom" means scrollTop is close to 0 (the visual bottom in a
   * reversed container is the DOM top).
   */
  function isNearBottom(): boolean {
    const el = scrollRef.current;
    if (!el) return true;
    return el.scrollTop > -120; // within ~120 px of the visual bottom
  }

  function scrollToBottom() {
    const el = scrollRef.current;
    if (el) el.scrollTop = 0;
  }

  // ── SSE real-time stream ───────────────────────────────────────────────────
  useEffect(() => {
    if (!slug || !data || !token) return;

    const url = `/api/v1/spaces/${slug}/channels/${activeChannel}/stream?token=${encodeURIComponent(token)}`;
    const es = new EventSource(url);

    es.addEventListener("message", (evt) => {
      try {
        const incoming: ChannelMessage = JSON.parse(evt.data);
        const wasNearBottom = isNearBottom();
        setMessages((prev) => {
          const merged = dedupMessages([incoming, ...prev]);
          return merged;
        });
        if (wasNearBottom) {
          requestAnimationFrame(scrollToBottom);
        }
      } catch {
        // Ignore malformed events
      }
    });

    es.onerror = () => {
      // Browser will auto-reconnect; nothing to do here
    };

    return () => es.close();
  }, [slug, activeChannel, data]);

  // ── Load more (older messages) ─────────────────────────────────────────────
  async function handleLoadMore() {
    if (!slug || !hasMore || loadingMore || messages.length === 0) return;
    const oldest = messages[messages.length - 1].id;
    setLoadingMore(true);
    try {
      const res = await listChannelMessages(slug, activeChannel, {
        before: oldest,
        limit: 50,
      });
      setMessages((prev) => dedupMessages([...prev, ...res.messages]));
      setHasMore(res.has_more);
    } finally {
      setLoadingMore(false);
    }
  }

  // ── Send message ───────────────────────────────────────────────────────────
  const handleSend = useCallback(
    async (content: string) => {
      if (!slug) return;
      // Optimistic placeholder
      const optimisticId = `optimistic-${Date.now()}`;
      const optimistic: ChannelMessage = {
        id: optimisticId,
        channel_id: activeChannel,
        author_id: "",
        author_username: username ?? "",
        author_display_name: username ?? "",
        author_avatar_url: null,
        content,
        edited_at: null,
        parent_id: null,
        created_at: new Date().toISOString(),
        reactions: {},
        viewer_reacted: [],
        attachments: [],
      };

      setMessages((prev) => dedupMessages([optimistic, ...prev]));
      scrollToBottom();

      try {
        const real = await sendChannelMessage(slug, activeChannel, { content });
        // Replace optimistic with real message
        setMessages((prev) =>
          dedupMessages(prev.map((m) => (m.id === optimisticId ? real : m))),
        );
        qc.invalidateQueries({ queryKey: ["channel-messages", slug, activeChannel] });
      } catch {
        // Remove the optimistic message on failure
        setMessages((prev) => prev.filter((m) => m.id !== optimisticId));
      }
    },
    [slug, activeChannel, username, qc],
  );

  // ── Reaction optimistic toggle ─────────────────────────────────────────────
  function handleReactionToggle(messageId: string, emoji: string) {
    setMessages((prev) =>
      prev.map((m) => {
        if (m.id !== messageId) return m;
        const alreadyReacted = m.viewer_reacted.includes(emoji);
        const newViewerReacted = alreadyReacted
          ? m.viewer_reacted.filter((e) => e !== emoji)
          : [...m.viewer_reacted, emoji];
        const currentCount = m.reactions[emoji] ?? 0;
        const newCount = alreadyReacted
          ? Math.max(0, currentCount - 1)
          : currentCount + 1;
        return {
          ...m,
          reactions: { ...m.reactions, [emoji]: newCount },
          viewer_reacted: newViewerReacted,
        };
      }),
    );
  }

  // ── Delete channel ─────────────────────────────────────────────────────────
  const [confirmDeleteChannel, setConfirmDeleteChannel] = useState<string | null>(null);

  async function handleDeleteChannel(channelSlug: string) {
    try {
      await deleteChannel(slug!, channelSlug);
      if (activeChannel === channelSlug) setSearchParams({});
      qc.invalidateQueries({ queryKey: ["space", slug] });
    } catch { /* ignore */ }
    setConfirmDeleteChannel(null);
  }

  // ── Create channel form ────────────────────────────────────────────────────
  const [showChannelForm, setShowChannelForm] = useState(false);
  const [channelName, setChannelName] = useState("");
  const [channelType, setChannelType] = useState<"text" | "announcement">("text");
  const [channelError, setChannelError] = useState("");

  async function handleCreateChannel(e: React.FormEvent) {
    e.preventDefault();
    if (!channelName.trim()) return;
    setChannelError("");
    try {
      await createChannel(slug!, { name: channelName.trim(), description: "", type: channelType });
      setChannelName("");
      setShowChannelForm(false);
      qc.invalidateQueries({ queryKey: ["space", slug] });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setChannelError(msg.includes("409") || msg.toLowerCase().includes("conflict") ? "A channel with that name already exists." : "Failed to create channel.");
    }
  }

  // ── Invite ─────────────────────────────────────────────────────────────────
  const [_inviteCode, setInviteCode] = useState("");
  const [copiedInvite, setCopiedInvite] = useState(false);

  async function handleCreateInvite() {
    try {
      const inv = await createSpaceInvite(slug!);
      const url = `${window.location.origin}/spaces/invite/${inv.code}`;
      setInviteCode(url);
      navigator.clipboard.writeText(url).catch(() => {});
      setCopiedInvite(true);
      setTimeout(() => setCopiedInvite(false), 3000);
    } catch { /* ignore */ }
  }

  // ── Join / leave ───────────────────────────────────────────────────────────
  const joinMutation = useMutation({
    mutationFn: () => joinSpace(slug!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["space", slug] }),
  });

  const leaveMutation = useMutation({
    mutationFn: () => leaveSpace(slug!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["space", slug] }),
  });

  // ── Render guards ──────────────────────────────────────────────────────────
  if (isLoading) return <Spinner />;
  if (error || !data) return (
    <div className="text-center py-16 text-gray-400 dark:text-gray-500">
      <p>Space not found or access denied.</p>
      <Link to="/spaces" className="text-brand hover:underline text-sm mt-2 inline-block">← Back to Spaces</Link>
    </div>
  );

  const { space, channels } = data;
  const isMember = space.is_member;
  const isOwner = space.viewer_role === "owner";
  const isMod = space.viewer_role === "moderator" || isOwner;
  const canModerate = isMod;
  const currentChannel = channels.find((ch: Channel) => ch.slug === activeChannel);

  // Messages in the list are stored newest-first (index 0 = most recent),
  // but we render using flex-col-reverse so they visually appear oldest→newest.
  // We need to reverse for display so oldest appears at top of DOM (= visual bottom).
  const displayMessages = [...messages].reverse();

  return (
    <div className="flex gap-0 -mx-4 -my-6 min-h-[calc(100vh-3.5rem)]">
      {/* ── Channels sidebar ────────────────────────────────────────────────── */}
      <aside className="w-56 shrink-0 bg-gray-50 dark:bg-gray-950 border-r border-gray-200 dark:border-gray-800 flex flex-col">
        {/* Space header */}
        <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-800">
          <div className="flex items-center gap-2">
            <span className="text-xl">{space.icon_emoji}</span>
            <div className="min-w-0">
              <h2 className="font-semibold text-sm text-gray-900 dark:text-gray-100 truncate">{space.name}</h2>
              <p className="text-xs text-gray-500 dark:text-gray-400">{space.member_count} members</p>
            </div>
          </div>
        </div>

        {/* Channel list */}
        <nav className="flex-1 p-2 overflow-y-auto">
          <div className="flex items-center justify-between px-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
              Channels
            </span>
            {isMod && (
              <button
                onClick={() => setShowChannelForm(!showChannelForm)}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
              >
                <Plus className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {showChannelForm && (
            <form onSubmit={handleCreateChannel} className="mb-2 px-2">
              <input
                value={channelName}
                onChange={(e) => setChannelName(e.target.value)}
                placeholder="channel-name"
                className="w-full px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-1 focus:ring-brand/40 mb-1"
              />
              <div className="flex gap-1 mb-1">
                {(["text", "announcement"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setChannelType(t)}
                    className={`text-xs px-2 py-0.5 rounded border transition-colors ${
                      channelType === t
                        ? "border-brand text-brand bg-brand/5"
                        : "border-gray-300 dark:border-gray-600 text-gray-500"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
              {channelError && (
                <p className="text-xs text-red-500 mb-1">{channelError}</p>
              )}
              <button
                type="submit"
                className="text-xs px-3 py-1 bg-brand text-white rounded hover:bg-brand-dark w-full"
              >
                Add
              </button>
            </form>
          )}

          {channels.map((ch: Channel) => (
            <div key={ch.id} className="group relative">
              {confirmDeleteChannel === ch.slug ? (
                <div className="px-2 py-1.5 text-xs">
                  <p className="text-gray-500 dark:text-gray-400 mb-1">Delete #{ch.name}?</p>
                  <div className="flex gap-1">
                    <button
                      onClick={() => handleDeleteChannel(ch.slug)}
                      className="px-2 py-0.5 bg-red-600 text-white rounded text-xs hover:bg-red-700"
                    >
                      Delete
                    </button>
                    <button
                      onClick={() => setConfirmDeleteChannel(null)}
                      className="px-2 py-0.5 border border-gray-300 dark:border-gray-600 text-gray-500 rounded text-xs hover:border-gray-400"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={() => setSearchParams({ channel: ch.slug })}
                  className={`w-full flex items-center gap-1.5 px-2 py-1.5 rounded text-sm transition-colors text-left ${
                    ch.slug === activeChannel
                      ? "bg-gray-200 dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                      : "text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-900 hover:text-gray-900 dark:hover:text-gray-200"
                  }`}
                >
                  {ch.type === "announcement"
                    ? <Megaphone className="w-3.5 h-3.5 shrink-0" />
                    : <Hash className="w-3.5 h-3.5 shrink-0" />
                  }
                  {(() => {
                    const count = unreadCounts?.[ch.slug] ?? 0;
                    const hasUnread = count > 0 && ch.slug !== activeChannel;
                    return (
                      <>
                        <span className={`truncate flex-1 ${hasUnread ? "font-semibold text-gray-900 dark:text-gray-100" : ""}`}>
                          {ch.name}
                        </span>
                        {hasUnread && (
                          <span className="ml-auto shrink-0 min-w-[18px] h-[18px] px-1 bg-brand text-white text-[10px] font-bold rounded-full flex items-center justify-center leading-none">
                            {count > 99 ? "99+" : count}
                          </span>
                        )}
                      </>
                    );
                  })()}
                  {isMod && (
                    <span
                      role="button"
                      onClick={(e) => { e.stopPropagation(); setConfirmDeleteChannel(ch.slug); }}
                      className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-red-100 dark:hover:bg-red-900/30 text-gray-400 hover:text-red-500 transition-opacity"
                    >
                      <Trash2 className="w-3 h-3" />
                    </span>
                  )}
                </button>
              )}
            </div>
          ))}
        </nav>

        {/* Footer actions */}
        <div className="p-2 border-t border-gray-200 dark:border-gray-800 space-y-1">
          {isOwner && space.is_private && (
            <button
              onClick={handleCreateInvite}
              className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-gray-500 dark:text-gray-400 hover:text-brand rounded hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors"
            >
              <Link2 className="w-3.5 h-3.5" />
              {copiedInvite ? "Copied!" : "Create invite"}
            </button>
          )}
          {isOwner && (
            <Link
              to={`/spaces/${slug}/settings`}
              className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-gray-500 dark:text-gray-400 hover:text-brand rounded hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors"
            >
              <Settings className="w-3.5 h-3.5" />
              Settings
            </Link>
          )}
          {isMember && !isOwner && (
            <button
              onClick={() => leaveMutation.mutate()}
              className="w-full flex items-center gap-2 px-2 py-1.5 text-xs text-red-400 hover:text-red-600 rounded hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              Leave space
            </button>
          )}
        </div>
      </aside>

      {/* ── Main chat area ──────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Channel header */}
        <div className="px-6 py-3 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between bg-white dark:bg-gray-900 shrink-0">
          <div className="flex items-center gap-2">
            {currentChannel?.type === "announcement"
              ? <Megaphone className="w-4 h-4 text-gray-400" />
              : <Hash className="w-4 h-4 text-gray-400" />
            }
            <span className="font-medium text-sm text-gray-900 dark:text-gray-100">
              {currentChannel?.name ?? activeChannel}
            </span>
            {currentChannel?.description && (
              <span className="text-xs text-gray-400 dark:text-gray-500 ml-1 hidden sm:block">
                — {currentChannel.description}
              </span>
            )}
            {space.is_private && <Lock className="w-3.5 h-3.5 text-gray-400 ml-1" />}
          </div>
          <div className="flex items-center gap-2">
            {!isMember && token && (
              <button
                onClick={() => joinMutation.mutate()}
                disabled={joinMutation.isPending}
                className="px-3 py-1.5 bg-brand text-white text-xs rounded-lg hover:bg-brand-dark transition-colors disabled:opacity-60"
              >
                Join Space
              </button>
            )}
          </div>
        </div>

        {/* Message list — flex-col-reverse keeps newest at bottom */}
        <div
          ref={scrollRef}
          className="flex-1 overflow-y-auto flex flex-col-reverse bg-white dark:bg-gray-900"
        >
          {/* Loading skeleton */}
          {messagesLoading && (
            <div className="flex items-center justify-center py-8">
              <Spinner />
            </div>
          )}

          {/* Non-member / logged-out notice */}
          {!messagesLoading && !isMember && !token && (
            <div className="text-center py-12 text-gray-400 dark:text-gray-500">
              <Hash className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="mb-2">
                {space.is_private
                  ? "This is a private space."
                  : "Join this space to participate."}
              </p>
              <Link to="/login" className="text-brand hover:underline text-sm">
                Log in
              </Link>
            </div>
          )}

          {/* Empty state for members */}
          {!messagesLoading && isMember && messages.length === 0 && (
            <div className="text-center py-12 text-gray-400 dark:text-gray-500">
              <Hash className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p className="font-medium">
                No messages in #{currentChannel?.name ?? activeChannel} yet.
              </p>
              <p className="text-sm mt-1">Be the first to say something!</p>
            </div>
          )}

          {/* Message rows — oldest at top (DOM top = visual top in flex-col-reverse context) */}
          <div className="flex flex-col py-2">
            {/* Load more older messages button */}
            {hasMore && (
              <div className="flex justify-center py-3">
                <button
                  onClick={handleLoadMore}
                  disabled={loadingMore}
                  className="flex items-center gap-1.5 px-4 py-1.5 text-xs text-gray-500 dark:text-gray-400 border border-gray-200 dark:border-gray-700 rounded-full hover:border-brand/40 hover:text-brand transition-colors disabled:opacity-50"
                >
                  <ChevronUp className="w-3.5 h-3.5" />
                  {loadingMore ? "Loading…" : "Load earlier messages"}
                </button>
              </div>
            )}

            {displayMessages.map((msg) => (
              <MessageBubble
                key={msg.id}
                message={msg}
                isOwn={msg.author_username === username}
                canModerate={canModerate}
                spaceSlug={slug!}
                channelSlug={activeChannel}
                onDeleted={(id) =>
                  setMessages((prev) => prev.filter((m) => m.id !== id))
                }
                onEdited={(updated) =>
                  setMessages((prev) =>
                    prev.map((m) => (m.id === updated.id ? updated : m)),
                  )
                }
                onReaction={handleReactionToggle}
              />
            ))}
          </div>
        </div>

        {/* Message input */}
        <MessageInput
          channelName={currentChannel?.name ?? activeChannel}
          disabled={!isMember || !token}
          onSend={handleSend}
        />
      </div>
    </div>
  );
}
