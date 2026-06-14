import React from "react";
import CodeBlock from "@/components/CodeBlock";
import YouTubeEmbed from "@/components/embeds/YouTubeEmbed";
import VimeoEmbed from "@/components/embeds/VimeoEmbed";
import TwitterEmbed from "@/components/embeds/TwitterEmbed";
import { detectEmbed } from "@/lib/embedUtils";

function renderInline(text: string, key: number): React.ReactNode {
  const parts: React.ReactNode[] = [];
  const re =
    /(\*\*(.+?)\*\*|\*(.+?)\*|`([^`]+)`|\[([^\]]+)\]\((https?:\/\/[^\)]+)\))/g;
  let last = 0;
  let m: RegExpExecArray | null;

  while ((m = re.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));

    if (m[2] !== undefined) {
      parts.push(<strong key={`b${m.index}`}>{m[2]}</strong>);
    } else if (m[3] !== undefined) {
      parts.push(<em key={`i${m.index}`}>{m[3]}</em>);
    } else if (m[4] !== undefined) {
      parts.push(
        <code
          key={`c${m.index}`}
          className="bg-gray-100 text-gray-800 px-1 py-0.5 rounded text-sm font-mono"
        >
          {m[4]}
        </code>
      );
    } else if (m[5] !== undefined && m[6] !== undefined) {
      parts.push(
        <a
          key={`a${m.index}`}
          href={m[6]}
          target="_blank"
          rel="noopener noreferrer"
          className="text-brand underline hover:text-brand-dark"
        >
          {m[5]}
        </a>
      );
    }

    last = m.index + m[0].length;
  }

  if (last < text.length) parts.push(text.slice(last));

  return <React.Fragment key={key}>{parts}</React.Fragment>;
}

export function renderBody(text: string): React.ReactNode {
  if (!text) return null;

  const lines = text.split("\n");
  const nodes: React.ReactNode[] = [];
  let i = 0;
  let nodeKey = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Fenced code block
    const codeOpenMatch = line.match(/^```(\w*)$/);
    if (codeOpenMatch) {
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].match(/^```\s*$/)) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++; // skip closing ```

      const lang = codeOpenMatch[1] || undefined;
      nodes.push(
        <CodeBlock key={nodeKey++} code={codeLines.join("\n")} language={lang} />
      );
      continue;
    }

    // Spoiler block
    const spoilerMatch = line.match(/^:::spoiler\s*(.*)/);
    if (spoilerMatch) {
      const title = spoilerMatch[1].trim();
      const contentLines: string[] = [];
      i++;
      while (i < lines.length && lines[i] !== ":::") {
        contentLines.push(lines[i]);
        i++;
      }
      if (i < lines.length && lines[i] === ":::") i++;

      nodes.push(
        <details
          key={nodeKey++}
          className="my-3 border border-amber-200 rounded-lg bg-amber-50 overflow-hidden"
        >
          <summary className="px-4 py-2 cursor-pointer text-sm font-medium text-amber-800 select-none hover:bg-amber-100 transition-colors list-none">
            🔒 {title || "Spoiler"}
          </summary>
          <div className="px-4 py-3 text-sm text-gray-700 whitespace-pre-wrap border-t border-amber-200">
            {contentLines.join("\n")}
          </div>
        </details>
      );
      continue;
    }

    // Headings
    const h3 = line.match(/^### (.+)/);
    const h2 = line.match(/^## (.+)/);
    const h1 = line.match(/^# (.+)/);
    if (h1) {
      nodes.push(
        <h1 key={nodeKey++} className="text-2xl font-bold text-gray-900 mt-6 mb-2">
          {renderInline(h1[1], nodeKey)}
        </h1>
      );
      i++;
      continue;
    }
    if (h2) {
      nodes.push(
        <h2 key={nodeKey++} className="text-xl font-bold text-gray-900 mt-5 mb-2">
          {renderInline(h2[1], nodeKey)}
        </h2>
      );
      i++;
      continue;
    }
    if (h3) {
      nodes.push(
        <h3 key={nodeKey++} className="text-lg font-semibold text-gray-900 mt-4 mb-1">
          {renderInline(h3[1], nodeKey)}
        </h3>
      );
      i++;
      continue;
    }

    // List items — collect consecutive
    if (line.match(/^[-*] /)) {
      const items: React.ReactNode[] = [];
      while (i < lines.length && lines[i].match(/^[-*] /)) {
        const content = lines[i].replace(/^[-*] /, "");
        items.push(<li key={i}>{renderInline(content, i)}</li>);
        i++;
      }
      nodes.push(
        <ul key={nodeKey++} className="list-disc list-inside my-2 space-y-0.5 text-gray-700">
          {items}
        </ul>
      );
      continue;
    }

    // Empty line
    if (line.trim() === "") {
      nodes.push(<br key={nodeKey++} />);
      i++;
      continue;
    }

    // Bare-URL embed detection — only when the entire trimmed line is a URL
    const trimmed = line.trim();
    const bareUrlMatch = trimmed.match(/^https?:\/\/\S+$/);
    if (bareUrlMatch) {
      const embedType = detectEmbed(trimmed);
      if (embedType === "youtube") {
        nodes.push(<YouTubeEmbed key={nodeKey++} url={trimmed} />);
        i++;
        continue;
      }
      if (embedType === "vimeo") {
        nodes.push(<VimeoEmbed key={nodeKey++} url={trimmed} />);
        i++;
        continue;
      }
      if (embedType === "twitter") {
        nodes.push(<TwitterEmbed key={nodeKey++} url={trimmed} />);
        i++;
        continue;
      }
    }

    // Plain paragraph line
    nodes.push(
      <span key={nodeKey++} className="block">
        {renderInline(line, nodeKey)}
      </span>
    );
    i++;
  }

  return <>{nodes}</>;
}
