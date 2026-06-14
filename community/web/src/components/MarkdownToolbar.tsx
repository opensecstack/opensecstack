import type { MutableRefObject } from "react";
import type { EditorView } from "@codemirror/view";
import {
  Bold, Italic, Strikethrough,
  List, ListOrdered, Quote,
  Code, Terminal, Link, Image, Minus, Lock,
} from "lucide-react";
import {
  wrapInline,
  prefixLine,
  insertCodeBlock,
  insertLink,
  insertImage,
  insertHR,
  insertSpoiler,
} from "@/lib/markdownEditorUtils";

interface Props {
  viewRef: MutableRefObject<EditorView | null>;
}

export default function MarkdownToolbar({ viewRef }: Props) {
  function run(fn: (view: EditorView) => boolean) {
    const view = viewRef.current;
    if (view) fn(view);
  }

  const cls =
    "p-1.5 rounded hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-100 transition-colors";
  const sep = <span className="w-px h-4 bg-gray-200 dark:bg-gray-600 mx-0.5 shrink-0" />;

  return (
    <div className="flex flex-wrap items-center gap-0.5 px-2 py-1.5 border border-b-0 border-gray-200 dark:border-gray-700 rounded-t-lg bg-gray-50 dark:bg-gray-800">
      <button type="button" title="Bold (Ctrl+B)" onClick={() => run((v) => wrapInline(v, "**", "**", "bold text"))} className={cls}>
        <Bold className="w-4 h-4" />
      </button>
      <button type="button" title="Italic (Ctrl+I)" onClick={() => run((v) => wrapInline(v, "*", "*", "italic text"))} className={cls}>
        <Italic className="w-4 h-4" />
      </button>
      <button type="button" title="Strikethrough" onClick={() => run((v) => wrapInline(v, "~~", "~~", "strikethrough"))} className={cls}>
        <Strikethrough className="w-4 h-4" />
      </button>

      {sep}

      <button type="button" title="Heading 1" onClick={() => run((v) => prefixLine(v, "# "))} className={`${cls} text-xs font-bold font-mono`}>
        H1
      </button>
      <button type="button" title="Heading 2" onClick={() => run((v) => prefixLine(v, "## "))} className={`${cls} text-xs font-bold font-mono`}>
        H2
      </button>
      <button type="button" title="Heading 3" onClick={() => run((v) => prefixLine(v, "### "))} className={`${cls} text-xs font-bold font-mono`}>
        H3
      </button>

      {sep}

      <button type="button" title="Unordered list" onClick={() => run((v) => prefixLine(v, "- "))} className={cls}>
        <List className="w-4 h-4" />
      </button>
      <button type="button" title="Ordered list" onClick={() => run((v) => prefixLine(v, "1. "))} className={cls}>
        <ListOrdered className="w-4 h-4" />
      </button>
      <button type="button" title="Blockquote" onClick={() => run((v) => prefixLine(v, "> "))} className={cls}>
        <Quote className="w-4 h-4" />
      </button>

      {sep}

      <button type="button" title="Inline code (Ctrl+`)" onClick={() => run((v) => wrapInline(v, "`", "`", "code"))} className={cls}>
        <Code className="w-4 h-4" />
      </button>
      <button type="button" title="Code block (Ctrl+Shift+K)" onClick={() => run(insertCodeBlock)} className={cls}>
        <Terminal className="w-4 h-4" />
      </button>

      {sep}

      <button type="button" title="Link (Ctrl+K)" onClick={() => run(insertLink)} className={cls}>
        <Link className="w-4 h-4" />
      </button>
      <button type="button" title="Image" onClick={() => run(insertImage)} className={cls}>
        <Image className="w-4 h-4" />
      </button>

      {sep}

      <button type="button" title="Horizontal rule" onClick={() => run(insertHR)} className={cls}>
        <Minus className="w-4 h-4" />
      </button>
      <button type="button" title="Spoiler block" onClick={() => run(insertSpoiler)} className={cls}>
        <Lock className="w-4 h-4" />
      </button>
    </div>
  );
}
