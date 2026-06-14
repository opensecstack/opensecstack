import { useState, useEffect, useCallback } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams, Link } from "react-router-dom";
import SEO from "@/components/SEO";
import { getUser, getUserPosts, getUserStats, getUserPinnedPost } from "@/api/users";
import { getFollowCounts, listFollowers, listFollowing, followUser, unfollowUser, getFollowStatus, type FollowUser } from "@/api/follows";
import UserStatsBar from "@/components/UserStatsBar";
import type { Post } from "@/api/posts";
import PostCard from "@/components/PostCard";
import Spinner from "@/components/Spinner";
import FollowButton from "@/components/FollowButton";
import BlockButton from "@/components/BlockButton";
import MuteButton from "@/components/MuteButton";
import { useAuthStore } from "@/state/auth";
import UserListModal from "@/components/UserListModal";

type Tab = "posts" | "followers" | "following";

const BADGE_STYLES: Record<string, string> = {
  Staff: "bg-indigo-100 text-indigo-700",
  Moderator: "bg-purple-100 text-purple-700",
  "Top Contributor": "bg-amber-100 text-amber-700",
  Verified: "bg-green-100 text-green-700",
  Alumni: "bg-gray-100 text-gray-600",
};

function ProfileBadge({ badge }: { badge: string }) {
  const cls = BADGE_STYLES[badge] ?? "bg-indigo-100 text-indigo-700";
  return (
    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
      {badge}
    </span>
  );
}

const POST_LIMIT = 20;

// ---------------------------------------------------------------------------
// UserCard — one row in the followers / following list
// ---------------------------------------------------------------------------

interface UserCardProps {
  user: FollowUser;
  showFollowButton: boolean;
}

function UserCard({ user, showFollowButton }: UserCardProps) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();

  const { data: statusData } = useQuery({
    queryKey: ["follow-status", user.username],
    queryFn: () => getFollowStatus(user.username),
    enabled: showFollowButton && !!token && me !== user.username,
  });

  const isFollowing = statusData?.following ?? false;

  async function toggle() {
    if (isFollowing) {
      await unfollowUser(user.username);
    } else {
      await followUser(user.username);
    }
    qc.invalidateQueries({ queryKey: ["follow-status", user.username] });
    qc.invalidateQueries({ queryKey: ["follow-counts"] });
  }

  return (
    <div className="flex items-center gap-3 p-3 border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
      {/* Avatar */}
      <div className="w-10 h-10 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-sm flex-shrink-0 overflow-hidden">
        {user.avatar_url ? (
          <img src={user.avatar_url} alt={user.display_name || user.username} className="w-full h-full object-cover" />
        ) : (
          (user.display_name?.[0] ?? user.username[0]).toUpperCase()
        )}
      </div>

      {/* Name + bio */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <Link
            to={`/users/${user.username}`}
            className="text-sm font-semibold hover:text-brand"
          >
            {user.display_name || user.username}
          </Link>
          {user.platform_badge && (
            <span className="text-xs bg-indigo-50 text-brand px-1.5 py-0.5 rounded">
              {user.platform_badge}
            </span>
          )}
          <span className="text-xs text-gray-400 dark:text-gray-500">@{user.username}</span>
        </div>
        {/* bio placeholder — FollowUser doesn't carry bio from the API yet; keep the slot */}
        {/* If the API ever returns bio, render it here */}
      </div>

      {/* Follow / Unfollow button */}
      {showFollowButton && (
        <button
          onClick={toggle}
          className={`flex-shrink-0 px-3 py-1 text-xs rounded-lg border transition-colors ${
            isFollowing
              ? "border-green-500 text-green-600 hover:bg-green-50"
              : "border-brand text-brand hover:bg-brand hover:text-white"
          }`}
        >
          {isFollowing ? "Following" : "Follow"}
        </button>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Profile page
// ---------------------------------------------------------------------------

export default function Profile() {
  const { username } = useParams<{ username: string }>();
  const { token, username: authUsername } = useAuthStore();
  const [activeTab, setActiveTab] = useState<Tab>("posts");
  const [showFollowers, setShowFollowers] = useState(false);
  const [showFollowing, setShowFollowing] = useState(false);

  // Posts load-more state
  const [userPosts, setUserPosts] = useState<Post[]>([]);
  const [postsOffset, setPostsOffset] = useState(0);
  const [postsHasMore, setPostsHasMore] = useState(true);
  const [postsLoading, setPostsLoading] = useState(false);
  const [postsTotalCount, setPostsTotalCount] = useState<number | null>(null);

  const { data: user, isLoading: userLoading } = useQuery({
    queryKey: ["user", username],
    queryFn: () => getUser(username!),
  });

  const { data: counts } = useQuery({
    queryKey: ["follow-counts", username],
    queryFn: () => getFollowCounts(username!),
    enabled: !!username,
  });

  const { data: stats } = useQuery({
    queryKey: ["user-stats", username],
    queryFn: () => getUserStats(username!),
    enabled: !!username,
  });

  const { data: pinnedData } = useQuery({
    queryKey: ["pinned-post", username],
    queryFn: () => getUserPinnedPost(username!),
    enabled: !!username,
    staleTime: 60_000,
  });
  const pinnedPost = pinnedData?.post ?? null;

  const { data: followersData, isLoading: followersLoading } = useQuery({
    queryKey: ["followers", username],
    queryFn: () => listFollowers(username!),
    enabled: !!username && activeTab === "followers",
  });

  const { data: followingData, isLoading: followingLoading } = useQuery({
    queryKey: ["following", username],
    queryFn: () => listFollowing(username!),
    enabled: !!username && activeTab === "following",
  });

  // Load user posts with pagination
  const loadUserPosts = useCallback(async (currentOffset: number, reset = false) => {
    if (!username) return;
    setPostsLoading(true);
    try {
      const data = await getUserPosts(username, POST_LIMIT, currentOffset);
      const newPosts = data.posts ?? [];
      setUserPosts((prev) => (reset ? newPosts : [...prev, ...newPosts]));
      setPostsHasMore(newPosts.length === POST_LIMIT);
      if (reset) setPostsTotalCount(data.count ?? null);
    } finally {
      setPostsLoading(false);
    }
  }, [username]);

  useEffect(() => {
    setUserPosts([]);
    setPostsOffset(0);
    setPostsHasMore(true);
    loadUserPosts(0, true);
  }, [username, loadUserPosts]);

  function handleLoadMorePosts() {
    const nextOffset = postsOffset + POST_LIMIT;
    setPostsOffset(nextOffset);
    loadUserPosts(nextOffset);
  }

  if (userLoading) return <Spinner />;
  if (!user) return <p className="text-center text-gray-400 py-12">User not found.</p>;

  const isOwnProfile = authUsername === username;
  const showFollowButton = !!token && !isOwnProfile;

  const displayCount = postsTotalCount ?? userPosts.length;
  const tabs: { id: Tab; label: string }[] = [
    { id: "posts", label: `Posts${displayCount > 0 ? ` (${displayCount})` : ""}` },
    { id: "followers", label: `Followers${counts ? ` (${counts.followers})` : ""}` },
    { id: "following", label: `Following${counts ? ` (${counts.following})` : ""}` },
  ];

  return (
    <div className="max-w-3xl mx-auto">
      <SEO
        title={user.display_name || user.username}
        description={user.bio || `${user.username}'s profile on SIN`}
        image={user.avatar_url ?? undefined}
        url={`${window.location.origin}/users/${user.username}`}
        type="profile"
        rssHref={`/api/v1/users/${user.username}/feed.rss`}
        rssTitle={`Posts by ${user.username} — SIN`}
      />
      {/* Profile header */}
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6 mb-6">
        <div className="flex items-center gap-4">
          <div className="w-16 h-16 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-2xl">
            {user.display_name?.[0] ?? user.username[0]}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-xl font-bold">{user.display_name || user.username}</h1>
              {token && <FollowButton username={user.username} />}
              <BlockButton username={user.username} />
              <MuteButton username={user.username} />
              {isOwnProfile && (
                <Link to="/settings" className="text-sm text-brand hover:underline">Edit profile</Link>
              )}
            </div>
            <p className="text-sm text-gray-500 dark:text-gray-400">@{user.username}</p>
            <p className="text-sm text-gray-400 dark:text-gray-500 flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setShowFollowers(true)}
                className="hover:text-brand dark:hover:text-brand transition-colors"
              >
                <span className="font-semibold text-gray-900 dark:text-gray-100">{counts?.followers ?? 0}</span> Followers
              </button>
              <span>·</span>
              <button
                onClick={() => setShowFollowing(true)}
                className="hover:text-brand dark:hover:text-brand transition-colors"
              >
                <span className="font-semibold text-gray-900 dark:text-gray-100">{counts?.following ?? 0}</span> Following
              </button>
            </p>
            {user.platform_badge && (
              <div className="mt-1">
                <ProfileBadge badge={user.platform_badge} />
              </div>
            )}
          </div>
        </div>
        {user.bio && <p className="mt-4 text-sm text-gray-600 dark:text-gray-400">{user.bio}</p>}

        {stats && <UserStatsBar stats={stats} />}

        {/* Profile details */}
        <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 text-sm text-gray-600 dark:text-gray-400">
          {user.location && <span>📍 {user.location}</span>}
          {user.website && (
            <a href={user.website} target="_blank" rel="noreferrer" className="hover:text-brand truncate max-w-[200px]">
              🔗 {user.website.replace(/^https?:\/\//, "")}
            </a>
          )}
          {user.github_username && (
            <a href={`https://github.com/${user.github_username}`} target="_blank" rel="noreferrer" className="hover:text-brand">
              GitHub: @{user.github_username}
            </a>
          )}
          {user.twitter_username && (
            <a href={`https://twitter.com/${user.twitter_username}`} target="_blank" rel="noreferrer" className="hover:text-brand">
              Twitter: @{user.twitter_username}
            </a>
          )}
        </div>

        {(user.certifications || user.specialization) && (
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            {user.certifications && (
              <span className="px-2 py-1 bg-brand/10 text-brand rounded-lg">🎓 {user.certifications}</span>
            )}
            {user.specialization && (
              <span className="px-2 py-1 bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 rounded-lg">⚙ {user.specialization}</span>
            )}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 dark:border-gray-700 mb-4">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-brand text-brand"
                : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === "posts" && (
        <div>
          {pinnedPost && (
            <div className="mb-6">
              <div className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 mb-2">
                <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                  <path d="M16 3a1 1 0 0 1 .707 1.707L15.414 6l1.293 1.293a1 1 0 0 1-1.414 1.414L14 7.414l-4.293 4.293A5.003 5.003 0 0 1 9 14H8l-2 2H4v-2l2-2v-1a5.003 5.003 0 0 1 2.293-.707l4.293-4.293-1.293-1.293a1 1 0 0 1 1.414-1.414L14 5.414l1.293-1.293A1 1 0 0 1 16 3z"/>
                </svg>
                <span>Pinned post</span>
              </div>
              <PostCard post={pinnedPost} />
            </div>
          )}
          {postsLoading && userPosts.length === 0 ? (
            <Spinner />
          ) : (
            <div className="space-y-4">
              {userPosts.map((p) => (
                <PostCard key={p.id} post={p} />
              ))}
              {!postsLoading && userPosts.length === 0 && (
                <p className="text-center text-gray-400 dark:text-gray-500 py-12">No published posts yet.</p>
              )}
            </div>
          )}
          {postsHasMore && (
            <div className="flex justify-center mt-6">
              <button
                onClick={handleLoadMorePosts}
                disabled={postsLoading}
                className="px-4 py-2 text-sm border border-gray-300 dark:border-gray-700 rounded-lg text-gray-700 dark:text-gray-300 hover:border-brand hover:text-brand transition-colors disabled:opacity-50"
              >
                {postsLoading ? "Loading…" : "Load more"}
              </button>
            </div>
          )}
          {!postsHasMore && userPosts.length > 0 && (
            <p className="text-center text-sm text-gray-400 dark:text-gray-500 mt-6">You've reached the end.</p>
          )}
        </div>
      )}

      {activeTab === "followers" && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          {followersLoading && (
            <div className="py-12 flex justify-center"><Spinner /></div>
          )}
          {!followersLoading && followersData?.users.length === 0 && (
            <p className="text-center text-gray-400 dark:text-gray-500 py-12">No followers yet.</p>
          )}
          {!followersLoading && followersData?.users.map((u) => (
            <UserCard
              key={u.username}
              user={u}
              showFollowButton={showFollowButton && u.username !== authUsername}
            />
          ))}
        </div>
      )}

      {activeTab === "following" && (
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          {followingLoading && (
            <div className="py-12 flex justify-center"><Spinner /></div>
          )}
          {!followingLoading && followingData?.users.length === 0 && (
            <p className="text-center text-gray-400 dark:text-gray-500 py-12">Not following anyone yet.</p>
          )}
          {!followingLoading && followingData?.users.map((u) => (
            <UserCard
              key={u.username}
              user={u}
              showFollowButton={showFollowButton && u.username !== authUsername}
            />
          ))}
        </div>
      )}

      {showFollowers && (
        <UserListModal
          title={`Followers of ${username}`}
          onClose={() => setShowFollowers(false)}
          fetchUsers={() => listFollowers(username!)}
          queryKey={["followers-modal", username!]}
        />
      )}
      {showFollowing && (
        <UserListModal
          title={`Following — ${username}`}
          onClose={() => setShowFollowing(false)}
          fetchUsers={() => listFollowing(username!)}
          queryKey={["following-modal", username!]}
        />
      )}
    </div>
  );
}
