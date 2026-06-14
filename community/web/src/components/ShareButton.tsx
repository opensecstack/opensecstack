import { useState } from "react";
import { Check } from "lucide-react";

interface ShareButtonProps {
  title: string;
  url: string;
  compact?: boolean;
}

export default function ShareButton({ title, url, compact = false }: ShareButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleShare = async () => {
    if (navigator.share) {
      try {
        await navigator.share({ title, url });
      } catch {
        // User cancelled or share failed — silently ignore
      }
      return;
    }

    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard unavailable — silently fail
    }
  };

  if (compact) {
    return (
      <button
        onClick={handleShare}
        title={copied ? "Copied!" : "Share"}
        aria-label="Share post"
        className="flex items-center gap-1 text-gray-400 dark:text-gray-500 hover:text-brand dark:hover:text-brand transition-colors"
      >
        {copied ? (
          <Check className="w-4 h-4 text-green-500" />
        ) : (
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13" />
          </svg>
        )}
        {copied && <span className="text-xs text-green-500">Copied!</span>}
      </button>
    );
  }

  return (
    <button
      onClick={handleShare}
      aria-label="Share post"
      className={`flex items-center gap-1.5 px-4 py-2 border rounded-lg text-sm transition-colors ${
        copied
          ? "bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700 text-green-600 dark:text-green-400"
          : "bg-white dark:bg-gray-900 border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-brand/40 hover:text-gray-700 dark:hover:text-gray-300"
      }`}
    >
      {copied ? (
        <>
          <Check className="w-4 h-4" />
          <span>Copied!</span>
        </>
      ) : (
        <>
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 12v8a2 2 0 002 2h12a2 2 0 002-2v-8M16 6l-4-4-4 4M12 2v13" />
          </svg>
          <span>Share</span>
        </>
      )}
    </button>
  );
}
