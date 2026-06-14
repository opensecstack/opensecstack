import { useEffect, useState } from "react";
import { apiClient } from "@/api/client";
import Spinner from "@/components/Spinner";
import { usePushSubscription } from "@/hooks/usePushSubscription";
import { useAuthStore } from "@/state/auth";

interface NotifPrefs {
  mention_email: boolean;
  digest_enabled: boolean;
  digest_frequency: "weekly" | "daily";
  email_follows: boolean;
  email_comments: boolean;
  email_reactions: boolean;
}

const NOTIF_CHECKBOXES: { key: keyof NotifPrefs; label: string }[] = [
  { key: "email_comments",  label: "Email me when someone comments on my post" },
  { key: "email_reactions", label: "Email me when someone reacts to my post" },
  { key: "email_follows",   label: "Email me when someone follows me" },
  { key: "mention_email",   label: "Email me when I'm mentioned in a comment" },
  { key: "digest_enabled",  label: "Send me a digest email" },
];

export default function NotificationsSection() {
  const { token } = useAuthStore();
  const push = usePushSubscription();

  const [notifPrefs, setNotifPrefs] = useState<NotifPrefs>({
    mention_email:    true,
    digest_enabled:   false,
    digest_frequency: "weekly",
    email_follows:    true,
    email_comments:   true,
    email_reactions:  false,
  });
  const [notifLoaded, setNotifLoaded] = useState(false);
  const [notifSaving, setNotifSaving] = useState(false);

  useEffect(() => {
    if (!token) return;
    apiClient.get("/api/v1/me/notification-preferences").then((res) => {
      setNotifPrefs(res.data);
      setNotifLoaded(true);
    });
  }, [token]);

  async function handleNotifChange(key: keyof NotifPrefs, value: boolean | string) {
    const updated = { ...notifPrefs, [key]: value };
    setNotifPrefs(updated);
    setNotifSaving(true);
    try {
      await apiClient.put("/api/v1/me/notification-preferences", updated);
    } finally {
      setNotifSaving(false);
    }
  }

  return (
    <>
      {/* Email Notifications */}
      <div className="mt-10 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
        <h2 className="font-semibold mb-1">Notifications</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">Choose which emails you receive from SIN.</p>
        {!notifLoaded ? (
          <Spinner />
        ) : (
          <div className="space-y-4">
            {NOTIF_CHECKBOXES.map(({ key, label }) => (
              <label key={key} className="flex items-center gap-3 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={notifPrefs[key] as boolean}
                  onChange={(e) => handleNotifChange(key, e.target.checked)}
                  className="w-4 h-4 rounded border-gray-300 text-brand focus:ring-brand/50"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
              </label>
            ))}
            {notifPrefs.digest_enabled && (
              <div className="ml-7 flex items-center gap-4">
                <span className="text-sm text-gray-600 dark:text-gray-400">Frequency:</span>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="digest_frequency"
                    value="weekly"
                    checked={notifPrefs.digest_frequency === "weekly"}
                    onChange={() => handleNotifChange("digest_frequency", "weekly")}
                    className="text-brand focus:ring-brand/50"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Weekly</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="radio"
                    name="digest_frequency"
                    value="daily"
                    checked={notifPrefs.digest_frequency === "daily"}
                    onChange={() => handleNotifChange("digest_frequency", "daily")}
                    className="text-brand focus:ring-brand/50"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Daily</span>
                </label>
              </div>
            )}
            {notifSaving && <p className="text-xs text-gray-400">Saving…</p>}
          </div>
        )}
      </div>

      {/* Push Notifications */}
      {push.supported && (
        <div className="mt-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
          <h2 className="font-semibold mb-1">Push Notifications</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            Receive browser push notifications for comments, reactions, and follows.
          </p>
          {push.permission === "denied" ? (
            <p className="text-sm text-yellow-700 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md px-3 py-2">
              Push notifications are blocked in your browser settings. To enable them, update the
              site permissions in your browser.
            </p>
          ) : (
            <label className="flex items-center gap-3 cursor-pointer select-none">
              <button
                type="button"
                role="switch"
                aria-checked={push.subscribed}
                disabled={push.loading}
                onClick={() => (push.subscribed ? push.unsubscribe() : push.subscribe())}
                className={`relative inline-flex h-6 w-11 shrink-0 rounded-full border-2 border-transparent transition-colors focus:outline-none focus:ring-2 focus:ring-brand/50 disabled:opacity-50 ${
                  push.subscribed ? "bg-brand" : "bg-gray-300 dark:bg-gray-600"
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform transition-transform ${
                    push.subscribed ? "translate-x-5" : "translate-x-0"
                  }`}
                />
              </button>
              <span className="text-sm text-gray-700 dark:text-gray-300">
                Browser push notifications
              </span>
              {push.subscribed && (
                <span className="text-xs text-green-600 dark:text-green-400">Notifications enabled</span>
              )}
            </label>
          )}
        </div>
      )}
    </>
  );
}
