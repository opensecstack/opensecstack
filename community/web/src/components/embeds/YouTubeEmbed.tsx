import { extractYouTubeId } from "@/lib/embedUtils";

interface Props {
  url: string;
}

export default function YouTubeEmbed({ url }: Props) {
  const videoId = extractYouTubeId(url);

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
        src={`https://www.youtube.com/embed/${videoId}`}
        title="YouTube video"
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        allowFullScreen
      />
    </div>
  );
}
