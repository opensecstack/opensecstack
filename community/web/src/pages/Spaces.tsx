import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { listSpaces, joinSpace, type Space } from "@/api/spaces";
import { useAuthStore } from "@/state/auth";
import { useState } from "react";
import Spinner from "@/components/Spinner";

export default function Spaces() {
  const { token } = useAuthStore();
  const navigate = useNavigate();
  const [joiningId, setJoiningId] = useState<string | null>(null);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["spaces"],
    queryFn: () => listSpaces(),
  });

  async function handleJoin(space: Space, e: React.MouseEvent) {
    e.preventDefault();
    if (!token) { navigate("/login"); return; }
    if (space.is_private) {
      navigate(`/spaces/${space.slug}`);
      return;
    }
    setJoiningId(space.id);
    try {
      await joinSpace(space.slug);
      await refetch();
      navigate(`/spaces/${space.slug}`);
    } finally {
      setJoiningId(null);
    }
  }

  if (isLoading) return <Spinner />;

  const spaces = data?.spaces ?? [];

  return (
    <div className="max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Spaces</h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Community spaces with channels — like Discord servers for SIN.
          </p>
        </div>
        {token && (
          <Link
            to="/spaces/new"
            className="px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
          >
            + Create Space
          </Link>
        )}
      </div>

      {spaces.length === 0 ? (
        <div className="text-center py-16 text-gray-400 dark:text-gray-500">
          <div className="text-5xl mb-4">🔷</div>
          <p className="font-medium mb-1">No spaces yet</p>
          <p className="text-sm">Be the first to create a community space.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {spaces.map((space) => (
            <Link
              key={space.id}
              to={`/spaces/${space.slug}`}
              className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-5 hover:border-brand/40 hover:shadow-sm transition-all group"
            >
              <div className="flex items-start gap-3">
                <span className="text-3xl">{space.icon_emoji}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="font-semibold text-gray-900 dark:text-gray-100 group-hover:text-brand truncate">
                      {space.name}
                    </h2>
                    {space.is_private && (
                      <span className="text-xs px-1.5 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400 rounded">
                        Private
                      </span>
                    )}
                  </div>
                  {space.description && (
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 line-clamp-2">
                      {space.description}
                    </p>
                  )}
                  <div className="flex items-center justify-between mt-3">
                    <span className="text-xs text-gray-400 dark:text-gray-500">
                      {space.member_count} {space.member_count === 1 ? "member" : "members"}
                    </span>
                    {space.is_member ? (
                      <span className="text-xs text-brand font-medium">Joined ✓</span>
                    ) : (
                      <button
                        onClick={(e) => handleJoin(space, e)}
                        disabled={joiningId === space.id}
                        className="text-xs px-3 py-1 bg-brand text-white rounded-lg hover:bg-brand-dark transition-colors disabled:opacity-50"
                      >
                        {joiningId === space.id ? "Joining…" : space.is_private ? "View" : "Join"}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}
