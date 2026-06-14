import { useEffect, useRef, useState } from "react";
import hljs from "highlight.js/lib/common";

interface Props {
  code: string;
  language?: string;
}

const ClipboardIcon = () => (
  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" />
  </svg>
)

const CheckIcon = () => (
  <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
  </svg>
)

export default function CodeBlock({ code, language }: Props) {
  const ref = useRef<HTMLElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (ref.current) {
      // Reset so hljs doesn't skip already-highlighted blocks
      ref.current.removeAttribute("data-highlighted");
      hljs.highlightElement(ref.current);
    }
  }, [code, language]);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // fallback: select all text in the pre element
    }
  };

  return (
    <div className="relative group my-4">
      <pre className="rounded-lg overflow-x-auto text-sm">
        <code ref={ref} className={language ? `language-${language}` : ""}>
          {code}
        </code>
      </pre>
      <button
        onClick={handleCopy}
        className={`absolute top-2 right-2 flex items-center gap-1 px-2 py-1 rounded text-xs font-medium transition-all
          opacity-0 group-hover:opacity-100
          ${copied ? "bg-green-700 text-white" : "bg-gray-700 hover:bg-gray-600 text-gray-200"}`}
        aria-label="Copy code"
      >
        {copied ? (
          <>
            <CheckIcon /> Copied!
          </>
        ) : (
          <>
            <ClipboardIcon /> Copy
          </>
        )}
      </button>
    </div>
  );
}
