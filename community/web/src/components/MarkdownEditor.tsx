import { useEffect, useRef, type MutableRefObject } from "react";
import { EditorView, keymap, placeholder as cmPlaceholder } from "@codemirror/view";
import { EditorState } from "@codemirror/state";
import { markdown } from "@codemirror/lang-markdown";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { HighlightStyle, syntaxHighlighting } from "@codemirror/language";
import { tags } from "@lezer/highlight";
import { wrapInline, insertLink, insertCodeBlock } from "@/lib/markdownEditorUtils";

const markdownHighlight = HighlightStyle.define([
  { tag: tags.heading1, fontWeight: "700", fontSize: "1.5em", lineHeight: "1.3", color: "#111827" },
  { tag: tags.heading2, fontWeight: "700", fontSize: "1.25em", color: "#1f2937" },
  { tag: tags.heading3, fontWeight: "600", fontSize: "1.1em", color: "#374151" },
  { tag: tags.heading, fontWeight: "600", color: "#374151" },
  { tag: tags.strong, fontWeight: "700" },
  { tag: tags.emphasis, fontStyle: "italic" },
  { tag: tags.strikethrough, textDecoration: "line-through" },
  { tag: tags.link, color: "#6366f1" },
  { tag: tags.url, color: "#6366f1" },
  { tag: tags.monospace, fontFamily: "'ui-monospace', monospace", color: "#be185d", backgroundColor: "rgba(190,24,93,0.07)", padding: "1px 3px", borderRadius: "3px" },
  { tag: tags.quote, color: "#6b7280", fontStyle: "italic" },
  { tag: tags.meta, color: "#9ca3af" },
  { tag: tags.processingInstruction, color: "#9ca3af" },
  { tag: tags.contentSeparator, color: "#d1d5db" },
  { tag: tags.list, color: "#6366f1" },
]);

const editorTheme = EditorView.theme({
  "&": {
    fontSize: "0.875rem",
    backgroundColor: "transparent",
  },
  ".cm-scroller": {
    fontFamily: "'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', monospace",
    lineHeight: "1.75",
    minHeight: "500px",
    overflow: "auto",
  },
  ".cm-content": {
    padding: "14px 16px",
    caretColor: "#6366f1",
    maxWidth: "100%",
  },
  "&.cm-focused": {
    outline: "none",
  },
  "&.cm-focused .cm-cursor": {
    borderLeftColor: "#6366f1",
    borderLeftWidth: "2px",
  },
  ".cm-activeLine": {
    backgroundColor: "rgba(99, 102, 241, 0.04)",
  },
  ".cm-selectionBackground": {
    backgroundColor: "rgba(99, 102, 241, 0.15) !important",
  },
  "&.cm-focused .cm-selectionBackground": {
    backgroundColor: "rgba(99, 102, 241, 0.2) !important",
  },
  ".cm-gutters": {
    display: "none",
  },
  ".cm-placeholder": {
    color: "#9ca3af",
    fontStyle: "italic",
  },
});

const markdownKeymap = [
  { key: "Mod-b", run: (view: EditorView) => wrapInline(view, "**", "**", "bold text") },
  { key: "Mod-i", run: (view: EditorView) => wrapInline(view, "*", "*", "italic text") },
  { key: "Mod-k", run: (view: EditorView) => insertLink(view) },
  { key: "Mod-`", run: (view: EditorView) => wrapInline(view, "`", "`", "code") },
  { key: "Mod-Shift-k", run: (view: EditorView) => insertCodeBlock(view) },
];

interface Props {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  viewRef?: MutableRefObject<EditorView | null>;
}

export default function MarkdownEditor({
  value,
  onChange,
  placeholder = "Write your post in Markdown…",
  viewRef,
}: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const internalViewRef = useRef<EditorView | null>(null);
  const isInternalChange = useRef(false);
  const onChangeRef = useRef(onChange);
  useEffect(() => { onChangeRef.current = onChange; }, [onChange]);

  useEffect(() => {
    if (!containerRef.current) return;

    const view = new EditorView({
      state: EditorState.create({
        doc: value,
        extensions: [
          history(),
          markdown(),
          syntaxHighlighting(markdownHighlight),
          keymap.of([...markdownKeymap, ...defaultKeymap, ...historyKeymap, indentWithTab]),
          EditorView.lineWrapping,
          cmPlaceholder(placeholder),
          editorTheme,
          EditorView.updateListener.of((update) => {
            if (update.docChanged) {
              isInternalChange.current = true;
              onChangeRef.current(update.state.doc.toString());
            }
          }),
        ],
      }),
      parent: containerRef.current,
    });

    internalViewRef.current = view;
    if (viewRef) viewRef.current = view;

    return () => {
      view.destroy();
      internalViewRef.current = null;
      if (viewRef) viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (isInternalChange.current) {
      isInternalChange.current = false;
      return;
    }
    const view = internalViewRef.current;
    if (!view) return;
    const current = view.state.doc.toString();
    if (current !== value) {
      view.dispatch({
        changes: { from: 0, to: current.length, insert: value },
      });
    }
  }, [value]);

  return (
    <div
      ref={containerRef}
      className="border border-gray-200 dark:border-gray-700 rounded-b-lg overflow-hidden bg-white dark:bg-gray-900 focus-within:ring-2 focus-within:ring-brand/40"
    />
  );
}
