import { extractVimeoId } from "@/lib/embedUtils";

interface Props {
  url: string;
}

export default function VimeoEmbed({ url }: Props) {
  const videoId = extractVimeoId(url);

  if (!videoId) {
    return (
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="text-brand underline hover:text-brand-dark break-all"
      >
        {url}
      </a>
    );
  }

  return (
    <div className="relative w-full my-4" style={{ paddingBottom: "56.25%" }}>
      <iframe
        className="absolute inset-0 w-full h-full rounded-lg"
        src={`https://player.vimeo.com/video/${videoId}`}
        title="Vimeo video"
        allow="autoplay; fullscreen; picture-in-picture"
        allowFullScreen
      />
    </div>
  );
}
