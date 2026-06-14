import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/state/auth";
import { getMuteStatus, muteUser, unmuteUser } from "@/api/mutes";

interface Props {
  username: string;
}

export default function MuteButton({ username }: Props) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();

  const { data } = useQuery({
    queryKey: ["mute-status", username],
    queryFn: () => getMuteStatus(username),
    enabled: !!token && me !== username,
  });

  const muteMutation = useMutation({
    mutationFn: () => muteUser(username),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mute-status", username] });
      qc.invalidateQueries({ queryKey: ["muted-users"] });
    },
  });

  const unmuteMutation = useMutation({
    mutationFn: () => unmuteUser(username),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mute-status", username] });
      qc.invalidateQueries({ queryKey: ["muted-users"] });
    },
  });

  if (!token || me === username) return null;

  const isMuted = data?.muted ?? false;
  const isPending = muteMutation.isPending || unmuteMutation.isPending;

  if (isMuted) {
    return (
      <button
        onClick={() => unmuteMutation.mutate()}
        disabled={isPending}
        className="text-sm px-3 py-1.5 border border-gray-300 rounded-lg text-gray-500 hover:border-gray-400 hover:text-gray-700 transition-colors disabled:opacity-50"
      >
        Unmute
      </button>
    );
  }

  return (
    <button
      onClick={() => muteMutation.mutate()}
      disabled={isPending}
      className="text-sm px-3 py-1.5 border border-gray-200 rounded-lg text-gray-400 hover:border-gray-400 hover:text-gray-600 transition-colors disabled:opacity-50"
    >
      Mute
    </button>
  );
}
