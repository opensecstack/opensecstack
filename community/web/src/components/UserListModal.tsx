import { useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { X } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import Spinner from "@/components/Spinner";

interface User {
  username: string;
  display_name: string;
  avatar_url?: string | null;
  platform_badge?: string | null;
}

interface UserListModalProps {
  title: string;
  onClose: () => void;
  fetchUsers: () => Promise<{ users: User[]; count: number }>;
  queryKey: string[];
}

export default function UserListModal({ title, onClose, fetchUsers, queryKey }: UserListModalProps) {
  const backdropRef = useRef<HTMLDivElement>(null);

  const { data, isLoading } = useQuery({
    queryKey,
    queryFn: fetchUsers,
  });

  // Close on Escape
  useEffect(() => {
    function onKey(e: KeyboardEvent) { if (e.key === "Escape") onClose(); }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      ref={backdropRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={(e) => { if (e.target === backdropRef.current) onClose(); }}
    >
      <div className="bg-white dark:bg-gray-900 rounded-xl shadow-xl w-full max-w-md mx-4 max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 dark:border-gray-800">
          <h2 className="font-semibold text-gray-900 dark:text-gray-100">{title}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="overflow-y-auto flex-1 px-2 py-2">
          {isLoading && <div className="flex justify-center py-8"><Spinner /></div>}
          {!isLoading && data?.users.length === 0 && (
            <p className="text-center text-gray-400 py-8 text-sm">No users yet.</p>
          )}
          {data?.users.map((u) => (
            <Link
              key={u.username}
              to={`/users/${u.username}`}
              onClick={onClose}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
            >
              <div className="w-9 h-9 rounded-full bg-brand/20 flex items-center justify-center text-brand font-bold text-sm flex-shrink-0 overflow-hidden">
                {u.avatar_url ? (
                  <img src={u.avatar_url} alt={u.display_name || u.username} className="w-full h-full object-cover" />
                ) : (
                  (u.display_name?.[0] ?? u.username[0]).toUpperCase()
                )}
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 flex-wrap">
                  <span className="font-medium text-sm text-gray-900 dark:text-gray-100 truncate">
                    {u.display_name || u.username}
                  </span>
                  {u.platform_badge && (
                    <span className="text-xs bg-indigo-50 text-brand px-1.5 py-0.5 rounded">
                      {u.platform_badge}
                    </span>
                  )}
                </div>
                <div className="text-xs text-gray-400 truncate">@{u.username}</div>
              </div>
            </Link>
          ))}
        </div>
      </div>
    </div>
  );
}
