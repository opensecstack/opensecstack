import { useState, useEffect, useRef, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Search } from "lucide-react";
import { fetchAutocomplete } from "@/api/search";
import type { AutocompletePost, AutocompleteTag, AutocompleteUser } from "@/api/search";

function useDebouncedValue<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

// Flat list item for keyboard navigation
type NavItem =
  | { kind: "post"; data: AutocompletePost }
  | { kind: "tag"; data: AutocompleteTag }
  | { kind: "user"; data: AutocompleteUser };

function itemHref(item: NavItem): string {
  if (item.kind === "post") return `/posts/${item.data.slug}`;
  if (item.kind === "tag") return `/tags/${item.data.slug}`;
  return `/users/${item.data.username}`;
}

interface Props {
  /** Called when the user submits a search query (instead of navigating to /search). */
  onSearch?: (q: string) => void;
  /** Pre-seed the input (e.g. from the URL on the Search page). */
  defaultValue?: string;
  placeholder?: string;
  autoFocus?: boolean;
}

export default function SearchAutocomplete({
  onSearch,
  defaultValue = "",
  placeholder = "Search posts…",
  autoFocus,
}: Props) {
  const navigate = useNavigate();
  const [input, setInput] = useState(defaultValue);

  // Keep input in sync when defaultValue changes (e.g. browser back/forward on Search page)
  useEffect(() => {
    setInput(defaultValue);
  }, [defaultValue]);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const containerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const debouncedQ = useDebouncedValue(input, 300);

  const { data, isFetching } = useQuery({
    queryKey: ["autocomplete", debouncedQ],
    queryFn: () => fetchAutocomplete(debouncedQ),
    enabled: debouncedQ.length >= 2,
    staleTime: 30_000,
  });

  const hasResults =
    data && (data.posts.length > 0 || data.tags.length > 0 || data.users.length > 0);

  // Build flat navigation list from results
  const navItems: NavItem[] = data
    ? [
        ...data.posts.map((p): NavItem => ({ kind: "post", data: p })),
        ...data.tags.map((t): NavItem => ({ kind: "tag", data: t })),
        ...data.users.map((u): NavItem => ({ kind: "user", data: u })),
      ]
    : [];

  // Reset active index when results change
  useEffect(() => {
    setActiveIndex(-1);
  }, [data]);

  // Show dropdown when there's a debounced query
  useEffect(() => {
    if (debouncedQ.length >= 2) {
      setOpen(true);
    } else {
      setOpen(false);
    }
  }, [debouncedQ]);

  // Close on click outside
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      const q = input.trim();
      if (!q) return;
      setOpen(false);
      if (onSearch) {
        onSearch(q);
      } else {
        navigate(`/search?q=${encodeURIComponent(q)}`);
      }
    },
    [input, navigate, onSearch],
  );

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!open) return;

    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, navItems.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, -1));
    } else if (e.key === "Enter" && activeIndex >= 0) {
      e.preventDefault();
      const item = navItems[activeIndex];
      if (item) {
        setOpen(false);
        setInput("");
        navigate(itemHref(item));
      }
    } else if (e.key === "Escape") {
      setOpen(false);
      setActiveIndex(-1);
    }
  }

  const showDropdown = open && debouncedQ.length >= 2;
  const showNoResults =
    showDropdown && !isFetching && data && !hasResults;

  return (
    <div ref={containerRef} className="relative flex-1 max-w-md">
      <form onSubmit={handleSubmit}>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 dark:text-gray-500 pointer-events-none" />
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            onFocus={() => {
              if (debouncedQ.length >= 2) setOpen(true);
            }}
            placeholder={placeholder}
            aria-label="Search"
            autoFocus={autoFocus}
            aria-autocomplete="list"
            aria-expanded={showDropdown}
            aria-activedescendant={
              activeIndex >= 0 ? `autocomplete-item-${activeIndex}` : undefined
            }
            className="w-full pl-9 pr-4 py-1.5 text-sm border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
          />
        </div>
      </form>

      {showDropdown && (
        <div
          role="listbox"
          className="absolute left-0 right-0 top-full mt-1 z-50 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg overflow-hidden"
        >
          {isFetching && !data && (
            <div className="px-4 py-3 text-sm text-gray-400 dark:text-gray-500">
              Loading…
            </div>
          )}

          {showNoResults && (
            <div className="px-4 py-3 text-sm text-gray-400 dark:text-gray-500">
              No suggestions
            </div>
          )}

          {hasResults && (
            <>
              {data!.posts.length > 0 && (
                <section>
                  <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                    Posts
                  </div>
                  {data!.posts.map((post, i) => {
                    const idx = i;
                    return (
                      <Link
                        key={post.id}
                        id={`autocomplete-item-${idx}`}
                        role="option"
                        aria-selected={activeIndex === idx}
                        to={`/posts/${post.slug}`}
                        onClick={() => {
                          setOpen(false);
                          setInput("");
                        }}
                        className={`flex items-center gap-2 px-4 py-2 text-sm transition-colors ${
                          activeIndex === idx
                            ? "bg-brand/10 text-brand"
                            : "text-gray-800 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800"
                        }`}
                      >
                        <Search className="w-3.5 h-3.5 shrink-0 text-gray-400" />
                        <span className="truncate">{post.title}</span>
                      </Link>
                    );
                  })}
                </section>
              )}

              {data!.tags.length > 0 && (
                <section>
                  <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                    Tags
                  </div>
                  {data!.tags.map((tag, i) => {
                    const idx = data!.posts.length + i;
                    return (
                      <Link
                        key={tag.slug}
                        id={`autocomplete-item-${idx}`}
                        role="option"
                        aria-selected={activeIndex === idx}
                        to={`/tags/${tag.slug}`}
                        onClick={() => {
                          setOpen(false);
                          setInput("");
                        }}
                        className={`flex items-center gap-2 px-4 py-2 text-sm transition-colors ${
                          activeIndex === idx
                            ? "bg-brand/10 text-brand"
                            : "text-gray-800 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800"
                        }`}
                      >
                        <span className="text-gray-400 font-medium">#</span>
                        <span>{tag.name}</span>
                      </Link>
                    );
                  })}
                </section>
              )}

              {data!.users.length > 0 && (
                <section>
                  <div className="px-3 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500">
                    Users
                  </div>
                  {data!.users.map((user, i) => {
                    const idx = data!.posts.length + data!.tags.length + i;
                    return (
                      <Link
                        key={user.username}
                        id={`autocomplete-item-${idx}`}
                        role="option"
                        aria-selected={activeIndex === idx}
                        to={`/users/${user.username}`}
                        onClick={() => {
                          setOpen(false);
                          setInput("");
                        }}
                        className={`flex items-center gap-2 px-4 py-2 text-sm transition-colors ${
                          activeIndex === idx
                            ? "bg-brand/10 text-brand"
                            : "text-gray-800 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-800"
                        }`}
                      >
                        {user.avatar_url ? (
                          <img
                            src={user.avatar_url}
                            alt=""
                            className="w-5 h-5 rounded-full object-cover shrink-0"
                          />
                        ) : (
                          <div className="w-5 h-5 rounded-full bg-brand/10 flex items-center justify-center text-[10px] font-bold text-brand shrink-0">
                            {(user.display_name || user.username)[0].toUpperCase()}
                          </div>
                        )}
                        <span className="truncate">
                          {user.display_name || user.username}
                          <span className="ml-1 text-gray-400 dark:text-gray-500">
                            @{user.username}
                          </span>
                        </span>
                      </Link>
                    );
                  })}
                </section>
              )}

              <div className="border-t border-gray-100 dark:border-gray-800 px-4 py-2">
                <button
                  type="button"
                  onMouseDown={(e) => {
                    // Use mousedown so it fires before blur
                    e.preventDefault();
                    const q = input.trim();
                    if (!q) return;
                    setOpen(false);
                    if (onSearch) {
                      onSearch(q);
                    } else {
                      navigate(`/search?q=${encodeURIComponent(q)}`);
                    }
                  }}
                  className="text-xs text-brand hover:underline"
                >
                  See all results for &ldquo;{input}&rdquo;
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}
