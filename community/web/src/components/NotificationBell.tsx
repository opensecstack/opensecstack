import React, { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useLocation } from "react-router-dom";
import { Bell, Sparkles } from "lucide-react";
import { listNotifications, markRead, markAllRead, type Notification } from "@/api/notifications";
import { useAuthStore } from "@/state/auth";
import EmptyState, { NotificationEmptyIcon } from "@/components/EmptyState";

function notificationMessage(n: Notification): { text: string; icon?: React.ReactNode } {
  const actor = n.actor_name || n.actor_username || "Someone";
  switch (n.type) {
    case "comment_on_post":
      return { text: `@${actor} commented on ${n.post_title ?? "a post"}` };
    case "reaction_on_post":
      return { text: `@${actor} reacted to ${n.post_title ?? "a post"}` };
    case "followed_by_user":
      return { text: `@${actor} started following you` };
    case "mentioned_in_comment":
      return { text: `@${actor} mentioned you in ${n.post_title ?? "a post"}` };
    case "welcome":
      return { text: "Welcome to SIN! Your account is ready.", icon: <Sparkles className="w-4 h-4 text-brand shrink-0" /> };
    case "password_changed":
      return { text: "Your password was changed successfully." };
    case "space_joined":
      return { text: `You joined ${n.space_name ?? "a space"}.` };
    case "space_member_joined":
      return { text: `@${actor} joined ${n.space_name ?? "your space"}.` };
    case "space_invite":
      return { text: `@${actor} invited you to join ${n.space_name ?? "a space"}.` };
    default:
      return { text: `@${actor}` };
  }
}

function notificationTarget(n: Notification): string {
  if (n.type === "followed_by_user" && n.actor_username) {
    return `/users/${n.actor_username}`;
  }
  if (n.type === "space_joined" || n.type === "space_member_joined" || n.type === "space_invite") {
    if (n.space_slug) return `/spaces/${n.space_slug}`;
  }
  if (n.post_slug) {
    return `/posts/${n.post_slug}`;
  }
  return "/";
}

export default function NotificationBell() {
  const { token } = useAuthStore();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const { data } = useQuery({
    queryKey: ["notifications"],
    queryFn: () => listNotifications(10),
    enabled: !!token,
    refetchInterval: 60_000,
  });

  // SSE connection using a short-lived one-time ticket so the JWT never
  // appears in server logs. On disconnect, waits 5 s then reconnects.
  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;

    async function connect() {
      if (cancelled) return;
      try {
        const res = await fetch("/api/v1/me/notifications/stream-ticket", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok || cancelled) return;
        const { ticket } = await res.json();
        if (cancelled) return;

        es = new EventSource(`/api/v1/me/notifications/stream?ticket=${encodeURIComponent(ticket)}`);

        es.addEventListener("unread_count", (e: MessageEvent) => {
          if (isNaN(parseInt(e.data, 10))) return;
          qc.invalidateQueries({ queryKey: ["notifications"] });
        });

        es.onerror = () => {
          es?.close();
          es = null;
          if (!cancelled) {
            retryTimer = setTimeout(connect, 5_000);
          }
        };
      } catch {
        if (!cancelled) {
          retryTimer = setTimeout(connect, 5_000);
        }
      }
    }

    connect();
    return () => {
      cancelled = true;
      es?.close();
      if (retryTimer) clearTimeout(retryTimer);
    };
  }, [token, qc]);

  useEffect(() => {
    setOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  if (!token) return null;

  const unread = data?.unread_count ?? 0;
  const notifications = data?.notifications ?? [];

  async function handleNotificationClick(n: Notification) {
    setOpen(false);
    if (!n.read) {
      await markRead(n.id);
      qc.invalidateQueries({ queryKey: ["notifications"] });
    }
    navigate(notificationTarget(n));
  }

  async function handleMarkAll() {
    await markAllRead();
    qc.invalidateQueries({ queryKey: ["notifications"] });
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="relative p-1.5 text-gray-500 hover:text-brand transition-colors"
        aria-label="Notifications"
      >
        <Bell className="w-5 h-5" />
        {unread > 0 && (
          <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-0.5 bg-red-500 text-white text-[10px] font-bold rounded-full flex items-center justify-center leading-none">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-[380px] bg-white border border-gray-200 rounded-lg shadow-lg z-50">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
            <span className="text-sm font-semibold text-gray-800">Notifications</span>
            {unread > 0 && (
              <button
                onClick={handleMarkAll}
                className="text-xs text-brand hover:text-brand-dark transition-colors"
              >
                Mark all read
              </button>
            )}
          </div>
          <div className="max-h-96 overflow-y-auto divide-y divide-gray-50">
            {notifications.length === 0 && (
              <EmptyState
                icon={<NotificationEmptyIcon />}
                title="All caught up!"
                description="No new notifications"
                size="sm"
              />
            )}
            {notifications.map((n) => {
              const { text, icon } = notificationMessage(n);
              return (
                <button
                  key={n.id}
                  onClick={() => handleNotificationClick(n)}
                  className={`w-full text-left px-4 py-3 text-sm transition-colors hover:bg-gray-50 dark:hover:bg-gray-800/50 flex items-start gap-2.5 ${
                    n.read ? "text-gray-500 dark:text-gray-400" : "bg-blue-50/60 dark:bg-brand/5 text-gray-700 dark:text-gray-200"
                  }`}
                >
                  {icon ?? <span className={`mt-0.5 w-1.5 h-1.5 rounded-full shrink-0 ${n.read ? "bg-transparent" : "bg-brand"}`} />}
                  <span>{text}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
