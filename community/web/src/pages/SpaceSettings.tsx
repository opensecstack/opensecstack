import { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { useQuery, useMutation } from "@tanstack/react-query";
import { getSpace, updateSpace, deleteSpace } from "@/api/spaces";
import Spinner from "@/components/Spinner";

const EMOJIS = ["🔷", "🛡️", "🔐", "🌐", "🧠", "⚡", "🔥", "🧩", "📡", "🎯", "🚀", "💡"];

export default function SpaceSettings() {
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();

  const { data, isLoading, error } = useQuery({
    queryKey: ["space", slug],
    queryFn: () => getSpace(slug!),
  });

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [iconEmoji, setIconEmoji] = useState("🔷");
  const [isPrivate, setIsPrivate] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saved, setSaved] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    if (data) {
      setName(data.space.name);
      setDescription(data.space.description);
      setIconEmoji(data.space.icon_emoji);
      setIsPrivate(data.space.is_private);
    }
  }, [data]);

  const updateMutation = useMutation({
    mutationFn: () => updateSpace(slug!, { name, description, icon_emoji: iconEmoji, is_private: isPrivate }),
    onSuccess: () => { setSaved(true); setTimeout(() => setSaved(false), 2000); },
    onError: () => setSaveError("Failed to save changes."),
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteSpace(slug!),
    onSuccess: () => navigate("/spaces"),
  });

  if (isLoading) return <Spinner />;
  if (error || !data) return (
    <div className="text-center py-16 text-gray-400">
      <p>Space not found.</p>
      <Link to="/spaces" className="text-brand hover:underline text-sm mt-2 inline-block">← Back to Spaces</Link>
    </div>
  );

  const isOwner = data.space.viewer_role === "owner";
  if (!isOwner) {
    return (
      <div className="text-center py-16 text-gray-400">
        <p>Access denied.</p>
        <Link to={`/spaces/${slug}`} className="text-brand hover:underline text-sm mt-2 inline-block">← Back</Link>
      </div>
    );
  }

  return (
    <div className="max-w-lg mx-auto">
      <div className="flex items-center gap-3 mb-6">
        <Link to={`/spaces/${slug}`} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 text-sm">← Back</Link>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">Space Settings</h1>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl p-6 space-y-5 mb-6">
        {saveError && (
          <div className="p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
            {saveError}
          </div>
        )}

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Icon</label>
          <div className="flex flex-wrap gap-2">
            {EMOJIS.map((em) => (
              <button key={em} type="button" onClick={() => setIconEmoji(em)}
                className={`text-2xl p-1.5 rounded-lg border-2 transition-colors ${iconEmoji === em ? "border-brand bg-brand/5" : "border-transparent hover:border-gray-300 dark:hover:border-gray-600"}`}>
                {em}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} maxLength={80}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand/40 text-sm" />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
          <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand/40 text-sm resize-none" />
        </div>

        <div className="flex items-center gap-3">
          <button type="button" role="switch" aria-checked={isPrivate} onClick={() => setIsPrivate(!isPrivate)}
            className={`relative inline-flex h-5 w-9 rounded-full transition-colors ${isPrivate ? "bg-brand" : "bg-gray-300 dark:bg-gray-600"}`}>
            <span className={`inline-block h-4 w-4 rounded-full bg-white shadow transform transition-transform mt-0.5 ${isPrivate ? "translate-x-4" : "translate-x-0.5"}`} />
          </button>
          <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Private space</span>
        </div>

        <button onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}
          className="px-5 py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark transition-colors disabled:opacity-50">
          {saved ? "Saved!" : updateMutation.isPending ? "Saving…" : "Save Changes"}
        </button>
      </div>

      <div className="bg-white dark:bg-gray-900 border border-red-200 dark:border-red-900/50 rounded-xl p-6">
        <h2 className="font-semibold text-red-600 dark:text-red-400 mb-2">Danger Zone</h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Deleting a space is permanent. All channels and posts will be removed.
        </p>
        {!confirmDelete ? (
          <button onClick={() => setConfirmDelete(true)}
            className="px-4 py-2 border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 text-sm rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
            Delete Space
          </button>
        ) : (
          <div className="flex gap-3">
            <button onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending}
              className="px-4 py-2 bg-red-600 text-white text-sm rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50">
              {deleteMutation.isPending ? "Deleting…" : "Confirm Delete"}
            </button>
            <button onClick={() => setConfirmDelete(false)}
              className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-500 text-sm rounded-lg hover:border-gray-400 transition-colors">
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
