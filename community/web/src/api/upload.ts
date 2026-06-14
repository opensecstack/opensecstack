import { useAuthStore } from "@/state/auth";

export async function uploadImage(file: File): Promise<string> {
  const token = useAuthStore.getState().token;
  const form = new FormData();
  form.append("file", file);

  const res = await fetch("/api/v1/upload", {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error ?? "Upload failed");
  }

  const data = (await res.json()) as { url: string };
  return data.url;
}
