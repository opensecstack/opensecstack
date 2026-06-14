import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listMySeries } from "@/api/series";
import Spinner from "@/components/Spinner";

export default function MySeries() {
  const { data, isLoading } = useQuery({
    queryKey: ["my-series"],
    queryFn: listMySeries,
  });

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">My Series</h1>
        <Link
          to="/series/new"
          className="px-4 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
        >
          Create new series
        </Link>
      </div>

      {isLoading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : data && data.length > 0 ? (
        <div className="space-y-4">
          {data.map((series) => (
            <div key={series.id} className="bg-white border border-gray-200 rounded-lg p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <Link
                    to={`/series/${series.slug}`}
                    className="text-lg font-semibold text-gray-900 hover:text-brand transition-colors"
                  >
                    {series.title}
                  </Link>
                  {series.description && (
                    <p className="text-sm text-gray-500 mt-1 line-clamp-2">{series.description}</p>
                  )}
                </div>
                <span className="flex-shrink-0 text-sm text-gray-400 whitespace-nowrap">
                  {series.post_count} {series.post_count === 1 ? "post" : "posts"}
                </span>
              </div>
              <div className="mt-3">
                <Link
                  to={`/series/${series.slug}`}
                  className="text-sm text-brand hover:underline"
                >
                  View series →
                </Link>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-white border border-gray-200 rounded-lg p-10 text-center">
          <p className="text-gray-500 mb-4">You haven't created any series yet.</p>
          <Link
            to="/series/new"
            className="inline-block px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors"
          >
            Create your first series
          </Link>
        </div>
      )}
    </div>
  );
}
