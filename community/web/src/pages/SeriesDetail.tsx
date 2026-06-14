import { useParams, useSearchParams, Link } from "react-router-dom";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getSeries, updateSeriesPostPosition, SeriesPost } from "@/api/series";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";

export default function SeriesDetail() {
  const { slug } = useParams<{ slug: string }>();
  const [searchParams] = useSearchParams();
  const currentPostSlug = searchParams.get("post");
  const { username } = useAuthStore();
  const qc = useQueryClient();

  const [dragging, setDragging] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["series", slug],
    queryFn: () => getSeries(slug!),
    enabled: !!slug,
  });

  const movePost = async (seriesId: string, posts: SeriesPost[], index: number, direction: "up" | "down") => {
    const swapIndex = direction === "up" ? index - 1 : index + 1;
    if (swapIndex < 0 || swapIndex >= posts.length) return;

    const posA = posts[index].position;
    const posB = posts[swapIndex].position;

    await updateSeriesPostPosition(seriesId, posts[index].id, posB);
    await updateSeriesPostPosition(seriesId, posts[swapIndex].id, posA);

    qc.invalidateQueries({ queryKey: ["series", slug] });
  };

  const handleDrop = async (seriesId: string, posts: SeriesPost[], targetPostId: string) => {
    if (!dragging || dragging === targetPostId) {
      setDragging(null);
      setDragOver(null);
      return;
    }

    const draggedPost = posts.find((p) => p.id === dragging);
    const targetPost = posts.find((p) => p.id === targetPostId);

    if (!draggedPost || !targetPost) {
      setDragging(null);
      setDragOver(null);
      return;
    }

    const newPosition = targetPost.position;

    await updateSeriesPostPosition(seriesId, draggedPost.id, newPosition);
    qc.invalidateQueries({ queryKey: ["series", slug] });

    setDragging(null);
    setDragOver(null);
  };

  if (isLoading) {
    return (
      <div className="flex justify-center py-12">
        <Spinner />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="max-w-3xl mx-auto">
        <div className="bg-white border border-gray-200 rounded-lg p-8 text-center">
          <p className="text-gray-500">Series not found.</p>
        </div>
      </div>
    );
  }

  const firstPost = data.posts.length > 0 ? data.posts[0] : null;

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <div className="mb-4">
          <h1 className="text-2xl font-bold text-gray-900">{data.title}</h1>
          <p className="text-sm text-gray-500 mt-1">
            By{" "}
            <Link to={`/users/${data.author_username}`} className="text-brand hover:underline">
              {data.author_name || data.author_username}
            </Link>
            {" · "}
            {data.posts.length} {data.posts.length === 1 ? "post" : "posts"}
          </p>
        </div>
        {data.description && (
          <p className="text-gray-600 text-sm leading-relaxed mb-4">{data.description}</p>
        )}
        {firstPost && (
          <Link
            to={`/posts/${firstPost.slug}`}
            className="inline-block px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
          >
            Start Reading
          </Link>
        )}
      </div>

      <div className="bg-white border border-gray-200 rounded-lg p-6">
        <h2 className="font-semibold text-gray-800 mb-4">Posts in this series</h2>
        {data.posts.length === 0 ? (
          <p className="text-sm text-gray-400 text-center py-6">No posts in this series yet.</p>
        ) : (
          <>
            <ol className="space-y-2">
              {[...data.posts].sort((a, b) => a.position - b.position).map((post, i, sorted) => {
                const isActive = currentPostSlug === post.slug;
                const isAuthor = username === data.author_username;
                const isDragging = dragging === post.id;
                const isDropTarget = dragOver === post.id && dragging !== post.id;
                return (
                  <li
                    key={post.id}
                    draggable={isAuthor}
                    onDragStart={isAuthor ? () => setDragging(post.id) : undefined}
                    onDragOver={isAuthor ? (e) => { e.preventDefault(); setDragOver(post.id); } : undefined}
                    onDrop={isAuthor ? () => handleDrop(data.id, sorted, post.id) : undefined}
                    onDragEnd={isAuthor ? () => { setDragging(null); setDragOver(null); } : undefined}
                    className={`flex items-center gap-3 rounded-lg px-2 py-1 transition-colors duration-150 ${
                      isDragging ? "opacity-50" : ""
                    } ${
                      isDropTarget
                        ? "ring-2 ring-indigo-400 bg-indigo-50 dark:bg-indigo-900/20"
                        : ""
                    }`}
                  >
                    {isAuthor && (
                      <span
                        className="flex-shrink-0 cursor-grab text-gray-400 hover:text-gray-600 select-none text-lg leading-none"
                        title="Drag to reorder"
                      >
                        ⠿
                      </span>
                    )}
                    <span
                      className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center text-xs font-semibold ${
                        isActive
                          ? "bg-brand text-white"
                          : "bg-gray-100 text-gray-500"
                      }`}
                    >
                      {post.position}
                    </span>
                    <Link
                      to={`/posts/${post.slug}`}
                      className={`flex-1 text-sm leading-6 hover:underline ${
                        isActive ? "text-brand font-medium" : "text-gray-700 hover:text-brand"
                      }`}
                    >
                      {post.title}
                    </Link>
                    {isAuthor && (
                      <div className="flex flex-col gap-0.5">
                        <button
                          onClick={() => movePost(data.id, sorted, i, "up")}
                          disabled={i === 0}
                          className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30"
                          title="Move up"
                        >
                          ↑
                        </button>
                        <button
                          onClick={() => movePost(data.id, sorted, i, "down")}
                          disabled={i === sorted.length - 1}
                          className="p-1 text-gray-400 hover:text-gray-600 disabled:opacity-30"
                          title="Move down"
                        >
                          ↓
                        </button>
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
            {username === data.author_username && data.posts.length >= 2 && (
              <p className="mt-3 text-xs text-gray-400 text-center">Drag to reorder</p>
            )}
          </>
        )}
      </div>
    </div>
  );
}
