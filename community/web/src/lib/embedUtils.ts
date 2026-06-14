export type EmbedType = "youtube" | "vimeo" | "twitter" | null;

export function detectEmbed(url: string): EmbedType {
  try {
    const u = new URL(url);
    if (u.hostname.includes("youtube.com") || u.hostname === "youtu.be")
      return "youtube";
    if (u.hostname.includes("vimeo.com")) return "vimeo";
    if (u.hostname.includes("twitter.com") || u.hostname.includes("x.com"))
      return "twitter";
  } catch {
    // not a valid URL
  }
  return null;
}

export function extractYouTubeId(url: string): string | null {
  try {
    const u = new URL(url);
    if (u.hostname === "youtu.be") return u.pathname.slice(1) || null;
    // youtube.com/embed/ID or youtube.com/watch?v=ID
    const v = u.searchParams.get("v");
    if (v) return v;
    const segments = u.pathname.split("/").filter(Boolean);
    // /embed/ID or /v/ID
    const embedIdx = segments.findIndex((s) => s === "embed" || s === "v");
    if (embedIdx !== -1 && segments[embedIdx + 1])
      return segments[embedIdx + 1];
    return null;
  } catch {
    return null;
  }
}

export function extractVimeoId(url: string): string | null {
  try {
    const segments = new URL(url).pathname.split("/").filter(Boolean);
    return segments.pop() ?? null;
  } catch {
    return null;
  }
}
