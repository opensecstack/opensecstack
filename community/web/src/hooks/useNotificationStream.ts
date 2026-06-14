import { useEffect, useState } from "react";
import { useAuthStore } from "@/state/auth";
import { listNotifications } from "@/api/notifications";

/**
 * Returns the current unread notification count, refreshed every 10 seconds.
 *
 * Note: The backend exposes a true SSE endpoint at GET /api/v1/me/notifications/stream,
 * but EventSource does not support the Authorization header. Since this app authenticates
 * via Bearer tokens only (no cookies), we fall back to polling with apiClient so the
 * token is attached automatically.
 */
export function useNotificationStream(): number {
  const token = useAuthStore((s) => s.token);
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    if (!token) {
      setUnreadCount(0);
      return;
    }

    const fetchCount = () => {
      listNotifications(1, 0)
        .then((r) => setUnreadCount(r.unread_count ?? 0))
        .catch(() => {});
    };

    fetchCount();
    const interval = setInterval(fetchCount, 10_000);
    return () => clearInterval(interval);
  }, [token]);

  return unreadCount;
}
