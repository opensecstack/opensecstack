import { useQuery, useQueryClient } from "@tanstack/react-query";
import { followUser, unfollowUser, getFollowStatus } from "@/api/follows";
import { useAuthStore } from "@/state/auth";

interface Props {
  username: string;
}

export default function FollowButton({ username }: Props) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ["follow-status", username],
    queryFn: () => getFollowStatus(username),
    enabled: !!token && me !== username,
  });

  if (!token || me === username) return null;

  async function toggle() {
    if (data?.following) {
      await unfollowUser(username);
    } else {
      await followUser(username);
    }
    qc.invalidateQueries({ queryKey: ["follow-status", username] });
  }

  return (
    <button
      onClick={toggle}
      disabled={isLoading}
      className="px-4 py-1.5 text-sm rounded-lg border border-brand text-brand hover:bg-brand hover:text-white transition-colors disabled:opacity-50"
    >
      {data?.following ? "Unfollow" : "Follow"}
    </button>
  );
}
