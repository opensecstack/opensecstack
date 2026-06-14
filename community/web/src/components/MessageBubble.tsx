import { useState } from "react";
import { Pencil, Trash2, Reply } from "lucide-react";
import {
  editChannelMessage,
  deleteChannelMessage,
  toggleMessageReaction,
  type ChannelMessage,
} from "@/api/channels";

// Quick-reaction emojis shown on hover
const QUICK_REACTIONS = ["👍", "❤️", "😂", "🔥"];

/** Format a UTC ISO date string as "Today at HH:MM" or "Mon DD at HH:MM". */
function formatMessageTime(isoString: string): string {
  const date = new Date(isoString);
  const now = new Date();

  const isToday =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate();

  const hh = String(date.getHours()).padStart(2, "0");
  const mm = String(date.getMinutes()).padStart(2, "0");
  const time = `${hh}:${mm}`;

  if (isToday) return `Today at ${time}`;

  const months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${months[date.getMonth()]} ${date.getDate()} at ${time}`;
}

/** Render plain-text content: split on newlines, join with <br />. */
function MessageContent({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <p className="text-sm text-gray-800 dark:text-gray-200 whitespace-pre-wrap break-words">
      {lines.map((line, i) => (
        <span key={i}>
          {line}
          {i < lines.length - 1 && <br />}
        </span>
      ))}
    </p>
  );
}

export interface MessageBubbleProps {
  message: ChannelMessage;
  isOwn: boolean;
  canModerate: boolean;
  spaceSlug: string;
  channelSlug: string;
  onDeleted: (id: string) => void;
  onEdited: (updated: ChannelMessage) => void;
  onReaction: (messageId: string, emoji: string) => void;
}

export default function MessageBubble({
  message,
  isOwn,
  canModerate,
  spaceSlug,
  channelSlug,
  onDeleted,
  onEdited,
  onReaction,
}: MessageBubbleProps) {
  const [hovered, setHovered] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState(message.content);
  const [editLoading, setEditLoading] = useState(false);
  const [editError, setEditError] = useState("");

  const canEdit = isOwn;
  const canDelete = isOwn || canModerate;

  const avatarLetter = (
    message.author_display_name || message.author_username
  )[0]?.toUpperCase() ?? "?";

  async function handleSaveEdit() {
    if (!editContent.trim()) return;
    setEditLoading(true);
    setEditError("");
    try {
      const updated = await editChannelMessage(
        spaceSlug,
        channelSlug,
        message.id,
        editContent.trim(),
      );
      onEdited(updated);
      setEditing(false);
    } catch {
      setEditError("Failed to save. Try again.");
    } finally {
      setEditLoading(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm("Delete this message?")) return;
    try {
      await deleteChannelMessage(spaceSlug, channelSlug, message.id);
      onDeleted(message.id);
    } catch {
      // ignore — could show a toast in a more complete implementation
    }
  }

  async function handleReaction(emoji: string) {
    try {
      await toggleMessageReaction(spaceSlug, channelSlug, message.id, emoji);
      onReaction(message.id, emoji);
    } catch {
      // ignore
    }
  }

  const reactionEntries = Object.entries(message.reactions).filter(
    ([, count]) => count > 0,
  );

  return (
    <div
      className="group relative flex items-start gap-3 px-4 py-1.5 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors"
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      {/* Avatar */}
      <div className="shrink-0 mt-0.5">
        {message.author_avatar_url ? (
          <img
            src={message.author_avatar_url}
            alt={message.author_username}
            className="w-9 h-9 rounded-full object-cover"
          />
        ) : (
          <div className="w-9 h-9 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-sm select-none">
            {avatarLetter}
          </div>
        )}
      </div>

      {/* Content column */}
      <div className="flex-1 min-w-0">
        {/* Header row */}
        <div className="flex items-baseline gap-2 mb-0.5 flex-wrap">
          {message.parent_id && (
            <span className="inline-flex items-center gap-1 text-xs text-gray-400 dark:text-gray-500 mr-1">
              <Reply className="w-3 h-3" />
              reply
            </span>
          )}
          <span className="font-semibold text-sm text-gray-900 dark:text-gray-100">
            {message.author_display_name || message.author_username}
          </span>
          <span className="text-xs text-gray-400 dark:text-gray-500">
            {formatMessageTime(message.created_at)}
          </span>
          {message.edited_at && (
            <span className="text-xs text-gray-400 dark:text-gray-500 italic">
              (edited)
            </span>
          )}
        </div>

        {/* Body — edit mode or display mode */}
        {editing ? (
          <div className="mt-1 space-y-1.5">
            <textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  handleSaveEdit();
                }
                if (e.key === "Escape") {
                  setEditing(false);
                  setEditContent(message.content);
                }
              }}
              rows={Math.min(6, Math.max(1, editContent.split("\n").length))}
              className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-brand/40 resize-none"
            />
            {editError && (
              <p className="text-xs text-red-500">{editError}</p>
            )}
            <div className="flex gap-2">
              <button
                onClick={handleSaveEdit}
                disabled={editLoading}
                className="px-3 py-1 text-xs bg-brand text-white rounded hover:bg-brand-dark disabled:opacity-50 transition-colors"
              >
                {editLoading ? "Saving…" : "Save"}
              </button>
              <button
                onClick={() => {
                  setEditing(false);
                  setEditContent(message.content);
                }}
                className="px-3 py-1 text-xs border border-gray-300 dark:border-gray-600 text-gray-500 rounded hover:border-gray-400 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <MessageContent text={message.content} />
        )}

        {/* Attachments */}
        {message.attachments.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-2">
            {message.attachments.map((att) => (
              <a
                key={att.id}
                href={att.file_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300 rounded border border-gray-200 dark:border-gray-700 hover:border-brand/50 transition-colors truncate max-w-xs"
              >
                📎 {att.file_name}
              </a>
            ))}
          </div>
        )}

        {/* Reaction chips */}
        {reactionEntries.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {reactionEntries.map(([emoji, count]) => {
              const hasReacted = message.viewer_reacted.includes(emoji);
              return (
                <button
                  key={emoji}
                  onClick={() => handleReaction(emoji)}
                  className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border transition-colors ${
                    hasReacted
                      ? "bg-brand/10 border-brand/40 text-brand dark:text-brand-light font-medium"
                      : "bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:border-brand/40"
                  }`}
                >
                  <span>{emoji}</span>
                  <span>{count}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Hover action bar — absolutely positioned top-right */}
      {hovered && !editing && (
        <div className="absolute top-0 right-3 -translate-y-1/2 flex items-center gap-0.5 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-sm px-1 py-0.5 z-10">
          {/* Quick reactions */}
          {QUICK_REACTIONS.map((emoji) => (
            <button
              key={emoji}
              onClick={() => handleReaction(emoji)}
              className="w-7 h-7 flex items-center justify-center text-sm rounded hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
              title={`React ${emoji}`}
            >
              {emoji}
            </button>
          ))}

          {canEdit && (
            <button
              onClick={() => setEditing(true)}
              className="w-7 h-7 flex items-center justify-center rounded hover:bg-gray-100 dark:hover:bg-gray-800 text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
              title="Edit message"
            >
              <Pencil className="w-3.5 h-3.5" />
            </button>
          )}

          {canDelete && (
            <button
              onClick={handleDelete}
              className="w-7 h-7 flex items-center justify-center rounded hover:bg-red-50 dark:hover:bg-red-900/20 text-gray-400 hover:text-red-500 transition-colors"
              title="Delete message"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}
    </div>
  );
}
