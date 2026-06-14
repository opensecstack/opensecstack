import { useState, useRef, useEffect } from "react";
import { listTags } from "@/api/tags";
import type { Tag } from "@/api/tags";

interface Props {
  value: string[];
  onChange: (tags: string[]) => void;
  maxTags?: number;
  placeholder?: string;
}

export default function TagInput({ value, onChange, maxTags = 5, placeholder = "Add tags…" }: Props) {
  const [input, setInput] = useState("");
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch all tags once on mount
  useEffect(() => {
    listTags(200).then((res) => setAllTags(res.tags)).catch(() => {});
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const trimmed = input.trim();

  const suggestions = trimmed.length > 0
    ? allTags
        .filter((t) => t.name.toLowerCase().includes(trimmed.toLowerCase()))
        .filter((t) => !value.some((v) => v.toLowerCase() === t.name.toLowerCase()))
        .slice(0, 8)
    : [];

  function addTag(name: string) {
    const cleaned = name.trim();
    if (!cleaned) return;
    if (value.length >= maxTags) return;
    if (value.some((v) => v.toLowerCase() === cleaned.toLowerCase())) return;
    onChange([...value, cleaned]);
    setInput("");
    setOpen(false);
    inputRef.current?.focus();
  }

  function removeTag(index: number) {
    onChange(value.filter((_, i) => i !== index));
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      e.preventDefault();
      if (trimmed) addTag(trimmed);
    } else if (e.key === "Backspace" && input === "" && value.length > 0) {
      onChange(value.slice(0, -1));
    } else if (e.key === "Escape") {
      setOpen(false);
    }
  }

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    setInput(e.target.value);
    setOpen(e.target.value.trim().length > 0);
  }

  // Highlight the matching portion of a tag name
  function highlight(name: string, query: string) {
    if (!query) return <span>{name}</span>;
    const idx = name.toLowerCase().indexOf(query.toLowerCase());
    if (idx === -1) return <span>{name}</span>;
    return (
      <>
        {name.slice(0, idx)}
        <span className="font-semibold text-brand">{name.slice(idx, idx + query.length)}</span>
        {name.slice(idx + query.length)}
      </>
    );
  }

  const atMax = value.length >= maxTags;

  return (
    <div ref={containerRef} className="relative">
      <div
        className="flex flex-wrap gap-1.5 items-center w-full text-sm border border-gray-300 rounded-lg p-3 focus-within:outline-none focus-within:ring-2 focus-within:ring-brand/40 cursor-text"
        onClick={() => inputRef.current?.focus()}
      >
        {value.map((tag, i) => (
          <span
            key={i}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-brand/10 text-brand text-sm"
          >
            {tag}
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); removeTag(i); }}
              className="leading-none hover:text-brand-dark focus:outline-none"
              aria-label={`Remove tag ${tag}`}
            >
              ×
            </button>
          </span>
        ))}
        {!atMax && (
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            onFocus={() => { if (trimmed) setOpen(true); }}
            placeholder={value.length === 0 ? placeholder : ""}
            className="flex-1 min-w-[120px] border-none outline-none bg-transparent text-sm placeholder-gray-400"
          />
        )}
        {atMax && (
          <span className="text-xs text-gray-400 ml-1">Max {maxTags} tags</span>
        )}
      </div>

      {open && (
        <div className="absolute left-0 right-0 top-full mt-1 z-50 bg-white border border-gray-200 rounded-lg shadow-md overflow-hidden">
          {suggestions.length > 0 ? (
            suggestions.map((tag) => (
              <button
                key={tag.id}
                type="button"
                onMouseDown={(e) => { e.preventDefault(); addTag(tag.name); }}
                className="w-full text-left py-1.5 px-3 text-sm hover:bg-gray-50 cursor-pointer"
              >
                {highlight(tag.name, trimmed)}
              </button>
            ))
          ) : (
            <div className="py-1.5 px-3 text-sm text-gray-400">
              No matching tags — press Enter to add <span className="font-medium text-gray-600">"{trimmed}"</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
