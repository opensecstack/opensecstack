import { useState, useRef, useEffect } from "react";
import { SendHorizonal, Smile } from "lucide-react";

const MAX_LENGTH = 4000;
const CHAR_WARN_THRESHOLD = 3800;

// Common emoji palette shown in the quick picker
const EMOJI_PALETTE = [
  "👍", "❤️", "😂", "🔥", "👏", "🎉",
  "🤔", "😮", "😢", "💯", "🚀", "✅",
];

export interface MessageInputProps {
  channelName: string;
  disabled?: boolean;
  onSend: (content: string) => Promise<void>;
}

export default function MessageInput({
  channelName,
  disabled = false,
  onSend,
}: MessageInputProps) {
  const [content, setContent] = useState("");
  const [sending, setSending] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const emojiPickerRef = useRef<HTMLDivElement>(null);

  // Auto-grow the textarea (1–6 rows)
  useEffect(() => {
    const ta = textareaRef.current;
    if (!ta) return;
    ta.style.height = "auto";
    const lineHeight = 24; // px — matches text-sm leading-6
    const maxHeight = lineHeight * 6;
    ta.style.height = `${Math.min(ta.scrollHeight, maxHeight)}px`;
  }, [content]);

  // Close emoji picker when clicking outside
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (
        emojiPickerRef.current &&
        !emojiPickerRef.current.contains(e.target as Node)
      ) {
        setShowEmojiPicker(false);
      }
    }
    if (showEmojiPicker) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [showEmojiPicker]);

  async function handleSend() {
    const trimmed = content.trim();
    if (!trimmed || sending || disabled) return;
    setSending(true);
    try {
      await onSend(trimmed);
      setContent("");
      // Reset textarea height after clearing
      if (textareaRef.current) {
        textareaRef.current.style.height = "auto";
      }
    } finally {
      setSending(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }

  function insertEmoji(emoji: string) {
    const ta = textareaRef.current;
    if (!ta) {
      setContent((c) => c + emoji);
      return;
    }
    const start = ta.selectionStart ?? content.length;
    const end = ta.selectionEnd ?? content.length;
    const next = content.slice(0, start) + emoji + content.slice(end);
    setContent(next);
    // Restore cursor position after React re-render
    requestAnimationFrame(() => {
      ta.focus();
      ta.setSelectionRange(start + emoji.length, start + emoji.length);
    });
    setShowEmojiPicker(false);
  }

  const charsLeft = MAX_LENGTH - content.length;
  const nearLimit = content.length >= CHAR_WARN_THRESHOLD;

  return (
    <div className="px-4 py-3 border-t border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900">
      {/* Emoji picker popover */}
      <div className="relative" ref={emojiPickerRef}>
        {showEmojiPicker && (
          <div className="absolute bottom-full mb-2 left-0 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-lg p-2 z-20">
            <div className="grid grid-cols-6 gap-1">
              {EMOJI_PALETTE.map((emoji) => (
                <button
                  key={emoji}
                  onClick={() => insertEmoji(emoji)}
                  className="w-8 h-8 flex items-center justify-center text-lg rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                >
                  {emoji}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Input row */}
        <div
          className={`flex items-end gap-2 border rounded-xl px-3 py-2 transition-colors ${
            disabled
              ? "bg-gray-50 dark:bg-gray-800/50 border-gray-200 dark:border-gray-700 opacity-60"
              : "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-600 focus-within:border-brand/50 focus-within:ring-1 focus-within:ring-brand/20"
          }`}
        >
          {/* Emoji toggle button */}
          <button
            type="button"
            onClick={() => !disabled && setShowEmojiPicker((v) => !v)}
            disabled={disabled}
            className="shrink-0 mb-0.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 disabled:pointer-events-none transition-colors"
            aria-label="Open emoji picker"
          >
            <Smile className="w-5 h-5" />
          </button>

          {/* Textarea */}
          <textarea
            ref={textareaRef}
            value={content}
            onChange={(e) => {
              if (e.target.value.length <= MAX_LENGTH) {
                setContent(e.target.value);
              }
            }}
            onKeyDown={handleKeyDown}
            disabled={disabled || sending}
            placeholder={disabled ? "Join the space to participate" : `Message #${channelName}`}
            rows={1}
            className="flex-1 resize-none bg-transparent text-sm text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none leading-6 max-h-36 overflow-y-auto disabled:cursor-not-allowed"
            style={{ minHeight: "1.5rem" }}
          />

          {/* Character count (only near limit) */}
          {nearLimit && (
            <span
              className={`shrink-0 text-xs mb-0.5 tabular-nums ${
                charsLeft <= 0
                  ? "text-red-500 font-semibold"
                  : "text-amber-500"
              }`}
            >
              {charsLeft}
            </span>
          )}

          {/* Send button */}
          <button
            type="button"
            onClick={handleSend}
            disabled={!content.trim() || sending || disabled}
            className="shrink-0 mb-0.5 w-7 h-7 flex items-center justify-center rounded-lg bg-brand text-white hover:bg-brand-dark disabled:opacity-40 disabled:pointer-events-none transition-colors"
            aria-label="Send message"
          >
            <SendHorizonal className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
