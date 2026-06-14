import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { useAuthStore } from "@/state/auth";
import TrendingTagsWidget from "./TrendingTagsWidget";
import SuggestedUsersWidget from "./SuggestedUsersWidget";
import { apiClient } from "@/api/client";

export default function Sidebar() {
  const { token, role } = useAuthStore();
  const [popularTags, setPopularTags] = useState<{id:string;name:string;slug:string;color:string;post_count:number}[]>([]);

  useEffect(() => {
    apiClient.get<{ tags: typeof popularTags }>("/tags/popular").then(r => setPopularTags(r.data.tags || [])).catch(() => {});
  }, []);

  return (
    <aside className="space-y-6">
      <TrendingTagsWidget />
      <SuggestedUsersWidget />
      {popularTags.length > 0 && (
        <div className="mt-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-2 px-2">
            Popular Tags
          </h3>
          <div className="space-y-1">
            {popularTags.map(tag => (
              <a key={tag.id} href={`/tags/${tag.slug}`}
                className="flex items-center justify-between px-2 py-1.5 rounded-md text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
                <span className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: tag.color }} />
                  {tag.name}
                </span>
                <span className="text-xs text-gray-400 dark:text-gray-500">{tag.post_count}</span>
              </a>
            ))}
          </div>
        </div>
      )}
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold text-gray-800 dark:text-gray-200">Spaces</h3>
          <Link to="/spaces" className="text-xs text-brand hover:underline">Browse all</Link>
        </div>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
          Community spaces with channels — like Discord servers for SIN.
        </p>
        <Link
          to="/spaces"
          className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
          Explore Spaces
        </Link>
      </div>
      {token && (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
          <h3 className="font-semibold text-gray-800 dark:text-gray-200 mb-3">My Content</h3>
          <div className="space-y-2">
            <Link
              to="/me/posts"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" />
              </svg>
              My Posts
            </Link>
            <Link
              to="/trending"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 0 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z" />
              </svg>
              Trending
            </Link>
            <Link
              to="/following"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
                <path d="M16 3.13a4 4 0 0 1 0 7.75" />
              </svg>
              Following
            </Link>
            <Link
              to="/bookmarks"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M19 21l-7-5-7 5V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2z" />
              </svg>
              Bookmarks
            </Link>
            <Link
              to="/me/series"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M4 6h16M4 10h16M4 14h10" />
              </svg>
              My Series
            </Link>
            <Link
              to="/series/new"
              className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors"
            >
              <svg
                xmlns="http://www.w3.org/2000/svg"
                className="w-4 h-4"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              Create Series
            </Link>
          </div>
        </div>
      )}
      {token && (role === "moderator" || role === "admin") && (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
          <h3 className="font-semibold text-gray-800 dark:text-gray-200 mb-3">Moderation</h3>
          <div className="space-y-2">
            <Link to="/mod/queue" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
              Mod Queue
            </Link>
            {role === "admin" && (
              <>
                <Link to="/admin/users" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  User Management
                </Link>
                <Link to="/admin/broadcast" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Broadcast
                </Link>
                <Link to="/admin/invites" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Invites
                </Link>
                <Link to="/admin/tags" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Tags
                </Link>
                <Link to="/admin/deletions" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Deletion Requests
                </Link>
                <Link to="/admin/audit" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Audit Log
                </Link>
                <Link to="/admin/stats" className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-300 hover:text-brand dark:hover:text-white transition-colors">
                  Statistics
                </Link>
              </>
            )}
          </div>
        </div>
      )}
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
        <h3 className="font-semibold text-gray-800 dark:text-gray-200 mb-2">About</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400">
          Share post-mortems, detection recipes, NIS2 guides, and CSAF advisory write-ups with the OpenSecStack community.
        </p>
      </div>
    </aside>
  );
}
