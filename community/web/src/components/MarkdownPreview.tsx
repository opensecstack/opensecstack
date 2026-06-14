import { renderBody } from "@/lib/renderBody";

interface Props {
  content: string;
  className?: string;
}

export default function MarkdownPreview({ content, className = "" }: Props) {
  return (
    <div className={`prose dark:prose-invert max-w-none ${className}`}>
      {renderBody(content)}
    </div>
  );
}
