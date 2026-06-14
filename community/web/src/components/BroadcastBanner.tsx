import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getBroadcast } from "@/api/admin";

export default function BroadcastBanner() {
  const { data } = useQuery({
    queryKey: ["broadcast"],
    queryFn: getBroadcast,
    refetchInterval: 60_000,
  });

  const broadcast = data?.broadcast ?? null;

  const [dismissed, setDismissed] = useState<boolean>(() => {
    if (!broadcast) return false;
    return sessionStorage.getItem(`broadcast-dismissed-${broadcast.id}`) === "true";
  });

  if (!broadcast || dismissed) return null;

  function dismiss() {
    if (!broadcast) return;
    sessionStorage.setItem(`broadcast-dismissed-${broadcast.id}`, "true");
    setDismissed(true);
  }

  return (
    <div className="bg-amber-500 text-white text-sm px-4 py-2 flex items-center gap-3">
      <span className="flex-1">{broadcast.body}</span>
      {broadcast.link_url && (
        <a href={broadcast.link_url} target="_blank" rel="noreferrer" className="underline shrink-0">
          Learn more
        </a>
      )}
      <button onClick={dismiss} className="shrink-0 opacity-80 hover:opacity-100">
        ✕
      </button>
    </div>
  );
}
