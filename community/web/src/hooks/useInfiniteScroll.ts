import { useRef, useEffect } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";

interface UseInfiniteScrollOptions<T> {
  queryKey: QueryKey;
  fetchFn: (page: number) => Promise<T[]>;
  enabled?: boolean;
}

export function useInfiniteScroll<T>({
  queryKey,
  fetchFn,
  enabled = true,
}: UseInfiniteScrollOptions<T>) {
  const sentinelRef = useRef<HTMLDivElement>(null);

  const { data, fetchNextPage, hasNextPage, isFetchingNextPage, status, error } =
    useInfiniteQuery({
      queryKey,
      queryFn: ({ pageParam }) => fetchFn(pageParam as number),
      initialPageParam: 1,
      getNextPageParam: (lastPage: T[], allPages) => {
        return lastPage.length < 20 ? undefined : allPages.length + 1;
      },
      enabled,
    });

  useEffect(() => {
    const el = sentinelRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && hasNextPage && !isFetchingNextPage) {
          fetchNextPage();
        }
      },
      { threshold: 0.1 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  return {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    status,
    error,
    ref: sentinelRef,
  };
}
