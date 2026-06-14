import { apiClient } from "./client";
import type { Post } from "./posts";

export interface AutocompletePost {
  id: number;
  title: string;
  slug: string;
}

export interface AutocompleteTag {
  slug: string;
  name: string;
}

export interface AutocompleteUser {
  username: string;
  display_name: string | null;
  avatar_url: string | null;
}

export interface AutocompleteResult {
  posts: AutocompletePost[];
  tags: AutocompleteTag[];
  users: AutocompleteUser[];
}

export async function fetchAutocomplete(q: string): Promise<AutocompleteResult> {
  const r = await apiClient.get("/api/v1/search/autocomplete", {
    params: { q },
  });
  return r.data;
}

export interface SearchResult {
  posts: Post[];
  count: number;
}

export async function searchPosts(
  q: string,
  limit = 20,
  offset = 0,
  filters?: { tag?: string; author?: string; from?: string; to?: string }
): Promise<SearchResult> {
  const params: Record<string, string | number> = { limit, offset };
  if (q) params.q = q;
  if (filters?.tag) params.tag = filters.tag;
  if (filters?.author) params.author = filters.author;
  if (filters?.from) params.from = filters.from;
  if (filters?.to) params.to = filters.to;
  const r = await apiClient.get("/api/v1/search", { params });
  return r.data;
}
