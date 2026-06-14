import { Fragment, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/state/auth";
import {
  listTags,
  adminCreateTag,
  adminUpdateTag,
  adminDeleteTag,
  fetchTagAliases,
  createTagAlias,
  deleteTagAlias,
  type Tag,
} from "@/api/tags";

interface CreateForm {
  name: string;
  description: string;
  color: string;
}

interface EditState {
  name: string;
  description: string;
  color: string;
}

const DEFAULT_COLOR = "#6366f1";
const ALIAS_RE = /^[a-z0-9-]+$/;

// ---------------------------------------------------------------------------
// TagAliasPanel — rendered as a colspan row beneath the tag row when expanded
// ---------------------------------------------------------------------------

interface TagAliasPanelProps {
  tagSlug: string;
}

function TagAliasPanel({ tagSlug }: TagAliasPanelProps) {
  const queryClient = useQueryClient();
  const [aliasInput, setAliasInput] = useState("");
  const [inputError, setInputError] = useState<string | null>(null);
  // Track which alias chip is currently being deleted
  const [deletingAlias, setDeletingAlias] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["tag-aliases", tagSlug],
    queryFn: () => fetchTagAliases(tagSlug),
  });

  const createMutation = useMutation({
    mutationFn: (alias: string) => createTagAlias(tagSlug, alias),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tag-aliases", tagSlug] });
      setAliasInput("");
      setInputError(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (alias: string) => deleteTagAlias(alias),
    onSuccess: (_data, alias) => {
      queryClient.invalidateQueries({ queryKey: ["tag-aliases", tagSlug] });
      setDeletingAlias((prev) => (prev === alias ? null : prev));
    },
    onError: () => {
      setDeletingAlias(null);
    },
  });

  function handleAddAlias(e: React.FormEvent) {
    e.preventDefault();
    const trimmed = aliasInput.trim().toLowerCase();
    if (!trimmed) {
      setInputError("Alias cannot be empty.");
      return;
    }
    if (!ALIAS_RE.test(trimmed)) {
      setInputError("Only lowercase letters, numbers, and hyphens are allowed.");
      return;
    }
    setInputError(null);
    createMutation.mutate(trimmed);
  }

  function handleDeleteAlias(alias: string) {
    setDeletingAlias(alias);
    deleteMutation.mutate(alias);
  }

  const aliases = data?.aliases ?? [];

  return (
    <div className="px-6 py-4 bg-gray-50 border-t border-gray-100">
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">
        Aliases for <span className="font-mono text-gray-700">{tagSlug}</span>
      </p>

      {isLoading && (
        <p className="text-xs text-gray-400 mb-3">Loading aliases…</p>
      )}

      {isError && (
        <p className="text-xs text-red-600 mb-3">Failed to load aliases.</p>
      )}

      {!isLoading && !isError && (
        <div className="flex flex-wrap gap-2 mb-3 min-h-[28px]">
          {aliases.length === 0 ? (
            <span className="text-xs text-gray-400 italic">No aliases yet.</span>
          ) : (
            aliases.map((a) => {
              const isBeingDeleted = deletingAlias === a.alias && deleteMutation.isPending;
              return (
                <span
                  key={a.alias}
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs bg-gray-200 text-gray-700 font-mono"
                >
                  {a.alias}
                  <button
                    onClick={() => handleDeleteAlias(a.alias)}
                    disabled={isBeingDeleted}
                    title={`Remove alias "${a.alias}"`}
                    className="ml-0.5 text-gray-500 hover:text-red-600 disabled:opacity-40 transition-colors leading-none"
                  >
                    {isBeingDeleted ? "…" : "×"}
                  </button>
                </span>
              );
            })
          )}
        </div>
      )}

      {deleteMutation.isError && (
        <p className="text-xs text-red-600 mb-2">Failed to delete alias. Please try again.</p>
      )}

      {/* Add alias form */}
      <form onSubmit={handleAddAlias} className="flex items-center gap-2">
        <input
          type="text"
          value={aliasInput}
          onChange={(e) => {
            setAliasInput(e.target.value.toLowerCase());
            setInputError(null);
          }}
          placeholder="e.g. js"
          className="text-xs border border-gray-300 rounded-md px-2.5 py-1.5 w-44 focus:outline-none focus:ring-2 focus:ring-brand/40"
        />
        <button
          type="submit"
          disabled={createMutation.isPending}
          className="px-3 py-1.5 bg-brand text-white text-xs rounded-md hover:bg-brand-dark disabled:opacity-50 transition-colors"
        >
          {createMutation.isPending ? "Adding…" : "Add alias"}
        </button>
      </form>

      {inputError && (
        <p className="mt-1 text-xs text-red-600">{inputError}</p>
      )}

      {createMutation.isError && (
        <p className="mt-1 text-xs text-red-600">
          {(createMutation.error as any)?.response?.data?.error ?? "Failed to create alias."}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AdminTags — main page
// ---------------------------------------------------------------------------

export default function AdminTags() {
  const { role } = useAuthStore();
  const queryClient = useQueryClient();

  // Create form state
  const [form, setForm] = useState<CreateForm>({ name: "", description: "", color: DEFAULT_COLOR });
  const [formError, setFormError] = useState<string | null>(null);

  // Inline edit state: slug of the row being edited
  const [editingSlug, setEditingSlug] = useState<string | null>(null);
  const [editState, setEditState] = useState<EditState>({ name: "", description: "", color: DEFAULT_COLOR });

  // Delete confirm state: slug of the row pending confirmation
  const [deletingSlug, setDeletingSlug] = useState<string | null>(null);

  // Expanded aliases panel: slug of the expanded row (only one at a time)
  const [expandedTag, setExpandedTag] = useState<string | null>(null);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["tags-admin"],
    queryFn: () => listTags(200),
    enabled: role === "admin",
  });

  const createMutation = useMutation({
    mutationFn: adminCreateTag,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags-admin"] });
      setForm({ name: "", description: "", color: DEFAULT_COLOR });
      setFormError(null);
    },
    onError: (err: any) => {
      setFormError(err?.response?.data?.error ?? "Failed to create tag.");
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ slug, data }: { slug: string; data: EditState }) => adminUpdateTag(slug, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags-admin"] });
      setEditingSlug(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: adminDeleteTag,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["tags-admin"] });
      setDeletingSlug(null);
    },
  });

  if (role !== "admin") {
    return <p>Access denied.</p>;
  }

  function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormError(null);
    if (!form.name.trim()) {
      setFormError("Name is required.");
      return;
    }
    createMutation.mutate({ name: form.name.trim(), description: form.description, color: form.color });
  }

  function startEdit(tag: Tag) {
    setEditingSlug(tag.slug);
    setEditState({ name: tag.name, description: tag.description, color: tag.color || DEFAULT_COLOR });
    setDeletingSlug(null);
  }

  function cancelEdit() {
    setEditingSlug(null);
  }

  function saveEdit(slug: string) {
    updateMutation.mutate({ slug, data: editState });
  }

  function handleDeleteClick(slug: string) {
    if (deletingSlug === slug) {
      deleteMutation.mutate(slug);
    } else {
      setDeletingSlug(slug);
      setEditingSlug(null);
    }
  }

  function toggleAliases(slug: string) {
    setExpandedTag((prev) => (prev === slug ? null : slug));
  }

  return (
    <div className="max-w-6xl mx-auto mt-8 px-4">
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Tag Management</h1>

      {/* Create form */}
      <div className="bg-white border border-gray-200 rounded-lg p-5 mb-8">
        <h2 className="text-sm font-semibold text-gray-700 uppercase tracking-wide mb-4">Create tag</h2>
        <form onSubmit={handleCreate} className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1 min-w-[160px]">
            <label className="text-xs text-gray-500 font-medium">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              placeholder="e.g. security"
              className="text-sm border border-gray-300 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
          </div>
          <div className="flex flex-col gap-1 flex-1 min-w-[200px]">
            <label className="text-xs text-gray-500 font-medium">Description</label>
            <input
              type="text"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
              placeholder="Short description (optional)"
              className="text-sm border border-gray-300 rounded-md px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-xs text-gray-500 font-medium">Color</label>
            <input
              type="color"
              value={form.color}
              onChange={(e) => setForm((f) => ({ ...f, color: e.target.value }))}
              className="h-[34px] w-14 border border-gray-300 rounded-md cursor-pointer p-0.5"
            />
          </div>
          <button
            type="submit"
            disabled={createMutation.isPending}
            className="px-4 py-1.5 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
          >
            {createMutation.isPending ? "Creating…" : "Create tag"}
          </button>
        </form>
        {formError && (
          <p className="mt-2 text-sm text-red-600">{formError}</p>
        )}
      </div>

      {/* Tag table */}
      {isLoading && <p className="text-sm text-gray-500">Loading tags…</p>}

      {isError && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to load tags.
        </div>
      )}

      {updateMutation.isError && (
        <div className="mb-4 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to update tag. The name or slug may already be in use.
        </div>
      )}

      {deleteMutation.isError && (
        <div className="mb-4 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
          Failed to delete tag. Please try again.
        </div>
      )}

      {data && (
        <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
          {data.tags.length === 0 ? (
            <p className="text-sm text-gray-500 p-6 text-center">No tags yet.</p>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-100 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">
                  <th className="px-4 py-3 w-8"></th>
                  <th className="px-4 py-3 w-10">Color</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Slug</th>
                  <th className="px-4 py-3">Description</th>
                  <th className="px-4 py-3 w-20">Posts</th>
                  <th className="px-4 py-3 w-52">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {data.tags.map((tag) => {
                  const isEditing = editingSlug === tag.slug;
                  const isDeleting = deletingSlug === tag.slug;
                  const isExpanded = expandedTag === tag.slug;

                  if (isEditing) {
                    return (
                      <tr key={tag.slug} className="bg-blue-50">
                        <td className="px-4 py-2" />
                        <td className="px-4 py-2">
                          <input
                            type="color"
                            value={editState.color}
                            onChange={(e) => setEditState((s) => ({ ...s, color: e.target.value }))}
                            className="h-7 w-10 border border-gray-300 rounded cursor-pointer p-0.5"
                          />
                        </td>
                        <td className="px-4 py-2">
                          <input
                            type="text"
                            value={editState.name}
                            onChange={(e) => setEditState((s) => ({ ...s, name: e.target.value }))}
                            className="text-sm border border-gray-300 rounded px-2 py-1 w-full focus:outline-none focus:ring-2 focus:ring-brand/40"
                          />
                        </td>
                        <td className="px-4 py-2 text-gray-400 text-xs font-mono">{tag.slug}</td>
                        <td className="px-4 py-2">
                          <input
                            type="text"
                            value={editState.description}
                            onChange={(e) => setEditState((s) => ({ ...s, description: e.target.value }))}
                            className="text-sm border border-gray-300 rounded px-2 py-1 w-full focus:outline-none focus:ring-2 focus:ring-brand/40"
                          />
                        </td>
                        <td className="px-4 py-2 text-gray-600">{tag.post_count}</td>
                        <td className="px-4 py-2 flex items-center gap-2">
                          <button
                            onClick={() => saveEdit(tag.slug)}
                            disabled={updateMutation.isPending}
                            className="px-3 py-1 bg-brand text-white text-xs rounded hover:bg-brand-dark disabled:opacity-50 transition-colors"
                          >
                            {updateMutation.isPending ? "Saving…" : "Save"}
                          </button>
                          <button
                            onClick={cancelEdit}
                            className="px-3 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 transition-colors"
                          >
                            Cancel
                          </button>
                        </td>
                      </tr>
                    );
                  }

                  return (
                    <Fragment key={tag.slug}>
                      <tr
                        className={`transition-colors ${isExpanded ? "bg-indigo-50" : "hover:bg-gray-50"}`}
                      >
                        {/* Expand toggle */}
                        <td className="px-2 py-3 text-center">
                          <button
                            onClick={() => toggleAliases(tag.slug)}
                            title={isExpanded ? "Hide aliases" : "Show aliases"}
                            className="text-gray-400 hover:text-gray-700 transition-colors text-xs leading-none select-none"
                          >
                            {isExpanded ? "▾" : "▸"}
                          </button>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className="inline-block w-5 h-5 rounded-full border border-gray-200"
                            style={{ backgroundColor: tag.color || DEFAULT_COLOR }}
                          />
                        </td>
                        <td className="px-4 py-3 font-medium text-gray-900">{tag.name}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{tag.slug}</td>
                        <td className="px-4 py-3 text-gray-600 max-w-xs truncate">
                          {tag.description || <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-4 py-3 text-gray-600">{tag.post_count}</td>
                        <td className="px-4 py-3">
                          {isDeleting ? (
                            <div className="flex items-center gap-2">
                              <span className="text-xs text-gray-600">All posts lose this tag.</span>
                              <button
                                onClick={() => handleDeleteClick(tag.slug)}
                                disabled={deleteMutation.isPending}
                                className="px-2 py-1 bg-red-600 text-white text-xs rounded hover:bg-red-700 disabled:opacity-50 transition-colors"
                              >
                                {deleteMutation.isPending ? "Deleting…" : "Yes, delete"}
                              </button>
                              <button
                                onClick={() => setDeletingSlug(null)}
                                className="px-2 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 transition-colors"
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => startEdit(tag)}
                                className="px-3 py-1 text-xs border border-gray-300 rounded hover:bg-gray-100 transition-colors"
                              >
                                Edit
                              </button>
                              <button
                                onClick={() => handleDeleteClick(tag.slug)}
                                className="px-3 py-1 text-xs border border-red-200 text-red-600 rounded hover:bg-red-50 transition-colors"
                              >
                                Delete
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>

                      {/* Inline aliases panel */}
                      {isExpanded && (
                        <tr className="bg-indigo-50">
                          <td colSpan={7} className="p-0">
                            <TagAliasPanel tagSlug={tag.slug} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
