import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/state/auth";

interface Stats {
  total_users: number;
  total_posts: number;
  total_comments: number;
  total_reactions: number;
  new_users_this_week: number;
  new_posts_this_week: number;
  top_tags: { name: string; slug: string; count: number }[];
  top_authors: { username: string; display_name: string; post_count: number }[];
}

export default function AdminStats() {
  const { role } = useAuthStore();

  const { data, isLoading, isError } = useQuery({
    queryKey: ["admin-stats"],
    queryFn: async () => {
      const res = await apiClient.get<Stats>("/api/v1/admin/stats");
      return res.data;
    },
    enabled: role === "admin" || role === "moderator",
  });

  if (role !== "admin" && role !== "moderator") {
    return <p>Access denied.</p>;
  }

  if (isLoading) return <div className="text-center py-12 text-gray-400">Loading…</div>;

  if (isError) {
    return (
      <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
        Failed to load statistics.
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="max-w-4xl mx-auto mt-8 px-4 space-y-8">
      <h1 className="text-2xl font-bold text-gray-900">Platform Statistics</h1>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Users", value: data.total_users, sub: `+${data.new_users_this_week} this week` },
          { label: "Published Posts", value: data.total_posts, sub: `+${data.new_posts_this_week} this week` },
          { label: "Comments", value: data.total_comments },
          { label: "Reactions", value: data.total_reactions },
        ].map((card) => (
          <div key={card.label} className="border border-gray-200 rounded-lg p-4 bg-white">
            <div className="text-2xl font-bold text-brand">{card.value.toLocaleString()}</div>
            <div className="text-sm font-medium text-gray-700 mt-1">{card.label}</div>
            {card.sub && <div className="text-xs text-gray-400 mt-1">{card.sub}</div>}
          </div>
        ))}
      </div>

      {/* Top tags + Top authors side by side */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="border border-gray-200 rounded-lg p-4 bg-white">
          <h2 className="font-semibold mb-3">Top Tags</h2>
          {data.top_tags.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-4">No tags yet.</p>
          ) : (
            <ol className="space-y-2">
              {data.top_tags.map((t, i) => (
                <li key={t.slug} className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 w-5">{i + 1}.</span>
                  <span className="flex-1 font-medium">{t.name}</span>
                  <span className="text-gray-400">{t.count} posts</span>
                </li>
              ))}
            </ol>
          )}
        </div>
        <div className="border border-gray-200 rounded-lg p-4 bg-white">
          <h2 className="font-semibold mb-3">Top Authors</h2>
          {data.top_authors.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-4">No authors yet.</p>
          ) : (
            <ol className="space-y-2">
              {data.top_authors.map((u, i) => (
                <li key={u.username} className="flex items-center justify-between text-sm">
                  <span className="text-gray-500 w-5">{i + 1}.</span>
                  <span className="flex-1 font-medium">{u.display_name || u.username}</span>
                  <span className="text-gray-400">{u.post_count} posts</span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </div>
  );
}
