import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { fetchRelatedPosts } from "@/api/posts";
import { timeAgo } from "@/lib/format";

interface Props {
  postId: string;
}

const PLACEHOLDER_COLORS = [
  "from-brand/20 to-brand/10",
  "from-purple-500/20 to-purple-500/10",
  "from-amber-500/20 to-amber-500/10",
  "from-emerald-500/20 to-emerald-500/10",
];

export default function RelatedPosts({ postId }: Props) {
  const { data } = useQuery({
    queryKey: ["related-posts", postId],
    queryFn: () => fetchRelatedPosts(postId),
    enabled: !!postId,
  });

  const posts = data?.posts ?? [];

  if (posts.length === 0) return null;

  return (
    <section className="mt-8">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">More like this</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {posts.map((post, i) => (
          <Link
            key={post.id}
            to={`/posts/${post.slug}`}
            className="group bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden hover:border-brand/40 hover:shadow-md transition-all duration-150"
          >
            {post.cover_image_url ? (
              <img
                src={post.cover_image_url}
                alt=""
                className="w-full h-36 object-cover"
              />
            ) : (
              <div
                className={`w-full h-36 bg-gradient-to-br ${PLACEHOLDER_COLORS[i % PLACEHOLDER_COLORS.length]}`}
              />
            )}
            <div className="p-4">
              <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100 line-clamp-2 group-hover:text-brand transition-colors">
                {post.title}
              </h3>
              <div className="flex items-center gap-2 mt-2">
                <div className="w-5 h-5 rounded-full bg-brand/20 flex items-center justify-center text-brand text-xs font-bold flex-shrink-0">
                  {(post.author.display_name || post.author.username)[0]}
                </div>
                <span className="text-xs text-gray-500 dark:text-gray-400 truncate">
                  {post.author.display_name || post.author.username}
                </span>
                <span className="text-xs text-gray-400 dark:text-gray-500 ml-auto flex-shrink-0">
                  {timeAgo(post.created_at)}
                </span>
              </div>
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
