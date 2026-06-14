import { EditorView } from "@codemirror/view";
import { EditorSelection } from "@codemirror/state";

export function wrapInline(view: EditorView, before: string, after: string, placeholder: string): boolean {
  const { state } = view;
  const changes = state.changeByRange((range) => {
    const selected = state.sliceDoc(range.from, range.to) || placeholder;
    return {
      changes: { from: range.from, to: range.to, insert: before + selected + after },
      range: EditorSelection.range(
        range.from + before.length,
        range.from + before.length + selected.length,
      ),
    };
  });
  view.dispatch(changes);
  view.focus();
  return true;
}

export function prefixLine(view: EditorView, prefix: string): boolean {
  const { state } = view;
  const { from } = state.selection.main;
  const line = state.doc.lineAt(from);

  if (line.text.startsWith(prefix)) {
    view.dispatch({
      changes: { from: line.from, to: line.from + prefix.length, insert: "" },
      selection: EditorSelection.cursor(Math.max(line.from, from - prefix.length)),
    });
  } else {
    view.dispatch({
      changes: { from: line.from, insert: prefix },
      selection: EditorSelection.cursor(from + prefix.length),
    });
  }
  view.focus();
  return true;
}

export function insertCodeBlock(view: EditorView): boolean {
  const { state } = view;
  const { from, to } = state.selection.main;
  const selected = state.sliceDoc(from, to) || "code here";
  const nl = from > 0 && state.sliceDoc(from - 1, from) !== "\n" ? "\n" : "";
  const block = nl + "```\n" + selected + "\n```\n";
  view.dispatch({
    changes: { from, to, insert: block },
    selection: EditorSelection.range(
      from + nl.length + 4,
      from + nl.length + 4 + selected.length,
    ),
  });
  view.focus();
  return true;
}

export function insertLink(view: EditorView): boolean {
  const { state } = view;
  const { from, to } = state.selection.main;
  const selected = state.sliceDoc(from, to) || "link text";
  view.dispatch({
    changes: { from, to, insert: `[${selected}](url)` },
    selection: EditorSelection.range(
      from + selected.length + 3,
      from + selected.length + 6,
    ),
  });
  view.focus();
  return true;
}

export function insertImage(view: EditorView): boolean {
  const { state } = view;
  const { from } = state.selection.main;
  const nl = from > 0 && state.sliceDoc(from - 1, from) !== "\n" ? "\n" : "";
  const insert = nl + "![alt text](image-url)";
  view.dispatch({
    changes: { from, insert },
    selection: EditorSelection.range(from + nl.length + 2, from + nl.length + 10),
  });
  view.focus();
  return true;
}

export function insertHR(view: EditorView): boolean {
  const { state } = view;
  const { from } = state.selection.main;
  const nl = from > 0 && state.sliceDoc(from - 1, from) !== "\n" ? "\n" : "";
  const insert = nl + "\n---\n\n";
  view.dispatch({
    changes: { from, insert },
    selection: EditorSelection.cursor(from + insert.length),
  });
  view.focus();
  return true;
}

export function insertSpoiler(view: EditorView): boolean {
  const { state } = view;
  const { from } = state.selection.main;
  const nl = from > 0 && state.sliceDoc(from - 1, from) !== "\n" ? "\n" : "";
  const insert = nl + ":::spoiler Spoiler Title\nHidden content here\n:::\n";
  view.dispatch({
    changes: { from, insert },
    selection: EditorSelection.cursor(from + insert.length),
  });
  view.focus();
  return true;
}
