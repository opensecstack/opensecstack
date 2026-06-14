import { useQuery } from "@tanstack/react-query";
import { useAuthStore } from "@/state/auth";
import { listMutedUsers } from "@/api/mutes";

export function useMutedUsers(): Set<string> {
  const { token } = useAuthStore();

  const { data } = useQuery({
    queryKey: ["muted-users"],
    queryFn: listMutedUsers,
    enabled: !!token,
    staleTime: 5 * 60 * 1000,
  });

  return new Set((data?.users ?? []).map((u) => u.username));
}
