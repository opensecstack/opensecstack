import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/state/auth";
import { blockUser, unblockUser, getBlockStatus } from "@/api/blocks";

interface Props {
  username: string;
}

export default function BlockButton({ username }: Props) {
  const { token, username: me } = useAuthStore();
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState(false);

  const { data } = useQuery({
    queryKey: ["block-status", username],
    queryFn: () => getBlockStatus(username),
    enabled: !!token && me !== username,
  });

  const blockMutation = useMutation({
    mutationFn: () => blockUser(username),
    onSuccess: () => {
      setConfirming(false);
      qc.invalidateQueries({ queryKey: ["block-status", username] });
    },
  });

  const unblockMutation = useMutation({
    mutationFn: () => unblockUser(username),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["block-status", username] });
    },
  });

  if (!token || me === username) return null;

  if (data?.blocking) {
    return (
      <button
        onClick={() => unblockMutation.mutate()}
        disabled={unblockMutation.isPending}
        className="text-sm px-3 py-1.5 border border-red-200 rounded-lg text-red-500 hover:bg-red-50 transition-colors disabled:opacity-50"
      >
        Unblock
      </button>
    );
  }

  if (confirming) {
    return (
      <div className="flex items-center gap-2">
        <span className="text-sm text-gray-500">Are you sure?</span>
        <button
          onClick={() => blockMutation.mutate()}
          disabled={blockMutation.isPending}
          className="text-sm px-3 py-1.5 border border-red-400 rounded-lg text-white bg-red-500 hover:bg-red-600 transition-colors disabled:opacity-50"
        >
          Yes, block
        </button>
        <button
          onClick={() => setConfirming(false)}
          disabled={blockMutation.isPending}
          className="text-sm px-3 py-1.5 border border-gray-200 rounded-lg text-gray-500 hover:bg-gray-50 transition-colors disabled:opacity-50"
        >
          Cancel
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => setConfirming(true)}
      className="text-sm px-3 py-1.5 border border-gray-200 rounded-lg text-gray-500 hover:border-red-300 hover:text-red-500 transition-colors"
    >
      Block
    </button>
  );
}
