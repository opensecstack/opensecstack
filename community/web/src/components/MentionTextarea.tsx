import { useState, useRef, useCallback } from "react";
import { searchUsers, UserHit } from "@/api/users";

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
  className?: string;
}

export default function MentionTextarea({ value, onChange, placeholder, rows = 3, className }: Props) {
  const [suggestions, setSuggestions] = useState<UserHit[]>([]);
  const [mentionQuery, setMentionQuery] = useState<string | null>(null);
  const [mentionStart, setMentionStart] = useState(0);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleChange = useCallback(async (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const v = e.target.value;
    onChange(v);

    const cursor = e.target.selectionStart ?? v.length;
    const before = v.slice(0, cursor);
    const match = before.match(/@([a-zA-Z0-9_]*)$/);
    if (match) {
      const q = match[1];
      setMentionQuery(q);
      setMentionStart(cursor - q.length - 1);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      debounceRef.current = setTimeout(async () => {
        if (q.length === 0) { setSuggestions([]); return; }
        const result = await searchUsers(q);
        setSuggestions(result.users as unknown as UserHit[]);
      }, 200);
    } else {
      setMentionQuery(null);
      setSuggestions([]);
    }
  }, [onChange]);

  function pickSuggestion(username: string) {
    const before = value.slice(0, mentionStart);
    const after = value.slice(mentionStart + (mentionQuery?.length ?? 0) + 1);
    const newValue = before + `@${username} ` + after;
    onChange(newValue);
    setSuggestions([]);
    setMentionQuery(null);
    textareaRef.current?.focus();
  }

  return (
    <div className="relative">
      <textarea
        ref={textareaRef}
        value={value}
        onChange={handleChange}
        placeholder={placeholder}
        rows={rows}
        className={className}
      />
      {suggestions.length > 0 && (
        <ul className="absolute z-50 bg-white border border-gray-200 rounded-lg shadow-md w-64 mt-1 overflow-hidden">
          {suggestions.map((u) => (
            <li key={u.username}>
              <button
                type="button"
                onMouseDown={(e) => { e.preventDefault(); pickSuggestion(u.username); }}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm hover:bg-gray-50 text-left"
              >
                <span className="font-medium text-gray-800">@{u.username}</span>
                {u.display_name && <span className="text-gray-400 truncate">{u.display_name}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
