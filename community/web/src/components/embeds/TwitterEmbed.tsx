interface Props {
  url: string;
}

export default function TwitterEmbed({ url }: Props) {
  return (
    <div className="border rounded-lg p-4 bg-gray-50 dark:bg-gray-800 max-w-lg my-4">
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-1">Tweet</p>
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="text-brand hover:underline break-all text-sm"
      >
        {url}
      </a>
      <p className="text-xs text-gray-400 dark:text-gray-500 mt-2">
        Open on X/Twitter ↗
      </p>
    </div>
  );
}
