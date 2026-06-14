import { useState, useEffect } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Hash, AtSign, X, ChevronDown, ChevronUp } from "lucide-react";
import { searchPosts } from "@/api/search";
import { searchUsers } from "@/api/users";
import PostCard from "@/components/PostCard";
import Spinner from "@/components/Spinner";
import EmptyState, { SearchEmptyIcon } from "@/components/EmptyState";
import SearchAutocomplete from "@/components/SearchAutocomplete";

export default function Search() {
  const [params, setParams] = useSearchParams();

  const q = params.get("q") ?? "";
  const tag = params.get("tag") ?? "";
  const author = params.get("author") ?? "";
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";

  const [tagInput, setTagInput] = useState(tag);
  const [authorInput, setAuthorInput] = useState(author);
  const [fromInput, setFromInput] = useState(from);
  const [toInput, setToInput] = useState(to);
  const [filtersOpen, setFiltersOpen] = useState(
    tag !== "" || author !== "" || from !== "" || to !== ""
  );
  const [tab, setTab] = useState<"posts" | "users">("posts");

  // Sync local state when URL params change externally (e.g. browser back/forward).
  useEffect(() => { setTagInput(tag); }, [tag]);
  useEffect(() => { setAuthorInput(author); }, [author]);
  useEffect(() => { setFromInput(from); }, [from]);
  useEffect(() => { setToInput(to); }, [to]);

  function applyFilters(overrides?: { q?: string; tag?: string; author?: string; from?: string; to?: string }) {
    const next = new URLSearchParams();
    const qVal = (overrides?.q ?? q).trim();
    const tagVal = (overrides?.tag ?? tagInput).trim();
    const authorVal = (overrides?.author ?? authorInput).trim();
    const fromVal = (overrides?.from ?? fromInput).trim();
    const toVal = (overrides?.to ?? toInput).trim();
    if (qVal) next.set("q", qVal);
    if (tagVal) next.set("tag", tagVal);
    if (authorVal) next.set("author", authorVal);
    if (fromVal) next.set("from", fromVal);
    if (toVal) next.set("to", toVal);
    setParams(next);
  }

  function handleAutocompleteSearch(newQ: string) {
    applyFilters({ q: newQ });
  }

  function clearFilters() {
    setTagInput("");
    setAuthorInput("");
    setFromInput("");
    setToInput("");
    const next = new URLSearchParams();
    if (q.trim()) next.set("q", q.trim());
    setParams(next);
  }

  const hasFilters = tag !== "" || author !== "" || from !== "" || to !== "";
  const hasAnyQuery = q !== "" || tag !== "" || author !== "" || from !== "" || to !== "";

  const { data, isLoading } = useQuery({
    queryKey: ["search", q, tag, author, from, to],
    queryFn: () =>
      searchPosts(q, 20, 0, {
        tag: tag || undefined,
        author: author || undefined,
        from: from || undefined,
        to: to || undefined,
      }),
    enabled: hasAnyQuery,
  });

  const { data: usersData, isLoading: usersLoading } = useQuery({
    queryKey: ["search-users", q],
    queryFn: () => searchUsers(q),
    enabled: q.length > 1 && tab === "users",
  });

  const resultLabel = (() => {
    if (!data) return null;
    const parts: string[] = [];
    if (q) parts.push(`"${q}"`);
    if (tag) parts.push(`#${tag}`);
    if (author) parts.push(`@${author}`);
    if (from && to) parts.push(`${from} – ${to}`);
    else if (from) parts.push(`from ${from}`);
    else if (to) parts.push(`until ${to}`);
    const qualifier = parts.length ? ` for ${parts.join(", ")}` : "";
    if (data.count === 0) return `No results${qualifier}`;
    return `${data.count} result${data.count !== 1 ? "s" : ""}${qualifier}`;
  })();

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-4 space-y-3">
        {/* Main search input with autocomplete */}
        <SearchAutocomplete
          defaultValue={q}
          onSearch={handleAutocompleteSearch}
          placeholder="Search posts, tags, or authors…"
          autoFocus
        />

        {/* Filters toggle */}
        <div>
          <button
            type="button"
            onClick={() => setFiltersOpen((o) => !o)}
            className="flex items-center gap-1 text-xs font-medium text-gray-500 hover:text-gray-700 transition-colors"
          >
            {filtersOpen ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
            Filters
            {hasFilters && (
              <span className="ml-1 inline-flex items-center justify-center w-4 h-4 rounded-full bg-brand text-white text-[10px]">
                {[tag, author, from, to].filter(Boolean).length}
              </span>
            )}
          </button>

          {filtersOpen && (
            <div className="mt-2 space-y-2">
              {/* Tag + Author row */}
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <Hash className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    placeholder="Tag"
                    aria-label="Tag"
                    className="w-full pl-9 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
                  />
                </div>
                <div className="relative flex-1">
                  <AtSign className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    value={authorInput}
                    onChange={(e) => setAuthorInput(e.target.value)}
                    placeholder="Author"
                    aria-label="Author"
                    className="w-full pl-9 pr-4 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
                  />
                </div>
              </div>

              {/* Date range row */}
              <div className="flex gap-3">
                <div className="flex-1">
                  <label className="block text-xs text-gray-500 mb-1">From</label>
                  <input
                    type="date"
                    value={fromInput}
                    onChange={(e) => setFromInput(e.target.value)}
                    aria-label="From date"
                    className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
                  />
                </div>
                <div className="flex-1">
                  <label className="block text-xs text-gray-500 mb-1">To</label>
                  <input
                    type="date"
                    value={toInput}
                    onChange={(e) => setToInput(e.target.value)}
                    aria-label="To date"
                    className="w-full px-3 py-2 text-sm border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand/40"
                  />
                </div>
              </div>

              {/* Clear filters */}
              {hasFilters && (
                <div className="flex justify-end">
                  <button
                    type="button"
                    onClick={clearFilters}
                    className="flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 transition-colors"
                  >
                    <X className="w-3 h-3" />
                    Clear filters
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {q.length > 1 && (
        <div className="flex gap-1 mb-4 border-b border-gray-200">
          {(["posts", "users"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize border-b-2 -mb-px transition-colors ${
                tab === t
                  ? "border-brand text-brand"
                  : "border-transparent text-gray-500 hover:text-gray-700"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      )}

      {!hasAnyQuery && (
        <EmptyState
          icon={<SearchEmptyIcon />}
          title="Search the community"
          description="Search for posts, tags, or authors"
        />
      )}

      {tab === "posts" && (
        <>
          {hasAnyQuery && isLoading && <Spinner />}

          {hasAnyQuery && !isLoading && data && (
            <>
              <p className="text-sm text-gray-500 mb-4">{resultLabel}</p>
              {data.count === 0 ? (
                <EmptyState
                  icon={<SearchEmptyIcon />}
                  title={`No results for "${[q, tag ? `#${tag}` : "", author ? `@${author}` : "", from ? `from ${from}` : "", to ? `until ${to}` : ""].filter(Boolean).join(", ")}"`}
                  description="Try different keywords or remove some filters"
                />
              ) : (
                <div className="space-y-4">
                  {data.posts.map((p) => (
                    <PostCard key={p.id} post={p} />
                  ))}
                </div>
              )}
            </>
          )}
        </>
      )}

      {tab === "users" && q.length > 1 && (
        <>
          {usersLoading && <Spinner />}
          {!usersLoading && usersData && (
            <>
              <p className="text-sm text-gray-500 mb-4">
                {usersData.count === 0
                  ? `No users for "${q}"`
                  : `${usersData.count} user${usersData.count !== 1 ? "s" : ""} for "${q}"`}
              </p>
              <div className="space-y-2">
                {usersData.users.map((u) => (
                  <Link
                    key={u.username}
                    to={`/users/${u.username}`}
                    className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg hover:border-brand/40 transition-colors"
                  >
                    {u.avatar_url ? (
                      <img src={u.avatar_url} alt="" className="w-10 h-10 rounded-full object-cover" />
                    ) : (
                      <div className="w-10 h-10 rounded-full bg-brand/10 flex items-center justify-center font-bold text-brand">
                        {(u.display_name || u.username)[0].toUpperCase()}
                      </div>
                    )}
                    <div>
                      <div className="font-medium text-sm">{u.display_name || u.username}</div>
                      <div className="text-xs text-gray-400">@{u.username}</div>
                      {u.bio && <div className="text-xs text-gray-500 mt-0.5 line-clamp-1">{u.bio}</div>}
                    </div>
                  </Link>
                ))}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}
