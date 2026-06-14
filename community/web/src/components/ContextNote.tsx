import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getContextNote, upsertContextNote, deleteContextNote } from "@/api/contextNotes";
import { useAuthStore } from "@/state/auth";
import { timeAgo } from "@/lib/format";

interface Props {
  postId: string;
}

export default function ContextNote({ postId }: Props) {
  const { role } = useAuthStore();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [editBody, setEditBody] = useState("");
  const [saving, setSaving] = useState(false);

  const { data } = useQuery({
    queryKey: ["context-note", postId],
    queryFn: () => getContextNote(postId),
  });

  const note = data?.note ?? null;
  const canEdit = role === "moderator" || role === "admin";

  if (!note && !canEdit) return null;

  async function handleSave() {
    if (!editBody.trim()) return;
    setSaving(true);
    try {
      await upsertContextNote(postId, editBody.trim());
      await qc.invalidateQueries({ queryKey: ["context-note", postId] });
      setEditing(false);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    await deleteContextNote(postId);
    await qc.invalidateQueries({ queryKey: ["context-note", postId] });
    setEditing(false);
  }

  function startEdit() {
    setEditBody(note!.body);
    setEditing(true);
  }

  if (!note && canEdit) {
    return (
      <div className="mt-4">
        {editing ? (
          <div className="p-4 bg-amber-50 border border-amber-200 rounded-lg flex flex-col gap-2">
            <span className="text-amber-600 font-semibold text-sm">📋 Add editorial note</span>
            <textarea
              className="w-full border border-amber-300 rounded-md px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-amber-400"
              rows={3}
              value={editBody}
              onChange={(e) => setEditBody(e.target.value)}
              placeholder="Add context for readers…"
            />
            <div className="flex gap-2">
              <button
                onClick={handleSave}
                disabled={saving || !editBody.trim()}
                className="px-3 py-1 bg-amber-600 text-white text-sm rounded-md hover:bg-amber-700 disabled:opacity-50"
              >
                {saving ? "Saving…" : "Save"}
              </button>
              <button
                onClick={() => setEditing(false)}
                className="px-3 py-1 border border-amber-300 text-amber-700 text-sm rounded-md hover:bg-amber-100"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => { setEditBody(""); setEditing(true); }}
            className="text-xs text-amber-600 border border-amber-200 px-3 py-1.5 rounded-lg hover:bg-amber-50"
          >
            + Add editorial note
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="mt-4 p-4 bg-amber-50 border border-amber-200 rounded-lg">
      <div className="flex items-start gap-2">
        <span className="text-amber-600 font-semibold text-sm shrink-0">📋 Editorial note</span>
        {editing ? (
          <div className="flex-1 flex flex-col gap-2">
            <textarea
              className="w-full border border-amber-300 rounded-md px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-amber-400"
              rows={3}
              value={editBody}
              onChange={(e) => setEditBody(e.target.value)}
            />
            <div className="flex gap-2">
              <button
                onClick={handleSave}
                disabled={saving || !editBody.trim()}
                className="px-3 py-1 bg-amber-600 text-white text-sm rounded-md hover:bg-amber-700 disabled:opacity-50"
              >
                {saving ? "Saving…" : "Save"}
              </button>
              <button
                onClick={() => setEditing(false)}
                className="px-3 py-1 border border-amber-300 text-amber-700 text-sm rounded-md hover:bg-amber-100"
              >
                Cancel
              </button>
            </div>
          </div>
        ) : (
          <p className="text-sm text-amber-800 flex-1">{note!.body}</p>
        )}
        {canEdit && !editing && (
          <div className="flex items-center gap-1 shrink-0">
            <button
              onClick={startEdit}
              className="text-xs text-amber-600 hover:text-amber-800 px-1 py-0.5 rounded hover:bg-amber-100"
              aria-label="Edit note"
            >
              Edit
            </button>
            <button
              onClick={handleDelete}
              className="text-xs text-amber-600 hover:text-red-600 px-1 py-0.5 rounded hover:bg-amber-100"
              aria-label="Delete note"
            >
              ×
            </button>
          </div>
        )}
      </div>
      <p className="text-xs text-amber-500 mt-1">
        Added by @{note!.author_username} · {timeAgo(note!.updated_at)}
      </p>
    </div>
  );
}
