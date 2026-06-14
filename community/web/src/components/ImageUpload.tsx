import { useRef, useState } from "react";
import { apiClient } from "@/api/client";

interface Props {
  value: string;
  onChange: (url: string) => void;
  label?: string;
}

export default function ImageUpload({ value, onChange, label = "Cover image" }: Props) {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = async (file: File) => {
    if (!file.type.startsWith("image/")) {
      setError("Please select an image file.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("File must be under 5 MB.");
      return;
    }
    setUploading(true);
    setError("");
    try {
      const fd = new FormData();
      fd.append("file", file);
      const r = await apiClient.post("/upload", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      onChange(r.data.url);
    } catch {
      setError("Upload failed. Please try again.");
    } finally {
      setUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleFile(file);
  };

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">{label}</label>

      {value ? (
        <div className="relative">
          <img src={value} alt="Cover" className="w-full h-48 object-cover rounded-lg border border-gray-200 dark:border-gray-700" />
          <button
            type="button"
            onClick={() => onChange("")}
            className="absolute top-2 right-2 bg-black/60 hover:bg-black/80 text-white text-xs px-2 py-1 rounded"
          >
            Remove
          </button>
        </div>
      ) : (
        <div
          onDrop={handleDrop}
          onDragOver={e => e.preventDefault()}
          onClick={() => inputRef.current?.click()}
          className="cursor-pointer border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center hover:border-indigo-400 dark:hover:border-indigo-500 transition-colors"
        >
          {uploading ? (
            <p className="text-sm text-gray-500 dark:text-gray-400">Uploading…</p>
          ) : (
            <>
              <p className="text-sm text-gray-500 dark:text-gray-400">Drag & drop or <span className="text-indigo-600 dark:text-indigo-400 underline">browse</span></p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">PNG, JPG, GIF, WebP · max 5 MB</p>
            </>
          )}
        </div>
      )}

      <input
        ref={inputRef}
        type="file"
        accept="image/*"
        className="hidden"
        onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
      />

      {/* Also allow manual URL input */}
      <input
        type="url"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder="Or paste image URL…"
        className="w-full text-sm border border-gray-200 dark:border-gray-700 rounded px-3 py-1.5 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100 placeholder-gray-400"
      />

      {error && <p className="text-xs text-red-500">{error}</p>}
    </div>
  );
}
