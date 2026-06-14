import { useEffect, useRef } from "react";
import { updatePost } from "@/api/posts";

export interface AutosaveOptions {
  postId: string | null;
  title: string;
  body: string;
  tags: string[];
  enabled: boolean;
  onSave?: (savedAt: Date) => void;
  onError?: (err: unknown) => void;
}

export function useAutosave(opts: AutosaveOptions): void {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep a ref to opts so the timeout callback always reads latest values
  // without the effect having to re-register on every keystroke.
  const optsRef = useRef(opts);
  optsRef.current = opts;

  useEffect(() => {
    if (timerRef.current) clearTimeout(timerRef.current);

    // Nothing to do — skip scheduling a save entirely.
    if (!opts.enabled || !opts.postId || (!opts.title.trim() && !opts.body.trim())) {
      return;
    }

    timerRef.current = setTimeout(async () => {
      const { postId, title, body, tags, onSave, onError } = optsRef.current;

      // Re-check guards inside the callback in case state changed during the wait.
      if (!postId || (!title.trim() && !body.trim())) return;

      try {
        await updatePost(postId, { title, body, tags });
        onSave?.(new Date());
      } catch (err) {
        onError?.(err);
      }
    }, 2000);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [opts.enabled, opts.postId, opts.title, opts.body, opts.tags]);
}
