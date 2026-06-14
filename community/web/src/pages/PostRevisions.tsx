import { useParams, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { getPost } from "@/api/posts";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/state/auth";
import Spinner from "@/components/Spinner";

interface Revision {
  id: string;
  title: string;
  body: string;
  revised_at: string;
}

export default function PostRevisions() {
  const { slug } = useParams<{ slug: string }>();
  const { username } = useAuthStore();

  const { data: post, isLoading: postLoading } = useQuery({
    queryKey: ["post", slug],
    queryFn: () => getPost(slug!),
  });

  const { data, isLoading } = useQuery({
    queryKey: ["revisions", post?.id],
    queryFn: async () => {
      const res = await apiClient.get<{ revisions: Revision[] }>(
        `/api/v1/posts/${post!.id}/revisions`
      );
      return res.data.revisions;
    },
    enabled: !!post?.id && post.author_username === username,
  });

  if (postLoading || isLoading) return <Spinner />;
  if (!post || post.author_username !== username)
    return <p className="text-center py-12 text-gray-400">Not found.</p>;

  return (
    <div className="max-w-2xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Revision History</h1>
        <Link to={`/posts/${slug}/edit`} className="text-sm text-brand hover:underline">
          ← Back to edit
        </Link>
      </div>
      {(!data || data.length === 0) ? (
        <p className="text-center text-gray-400 py-12">No revisions yet.</p>
      ) : (
        <div className="space-y-4">
          {data.map((rev) => (
            <div key={rev.id} className="border border-gray-200 rounded-lg p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium text-sm">{rev.title}</span>
                <span className="text-xs text-gray-400">
                  {new Date(rev.revised_at).toLocaleString()}
                </span>
              </div>
              <p className="text-sm text-gray-500 line-clamp-3">{rev.body}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
