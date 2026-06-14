import { useEffect, useRef, useCallback } from "react";

interface LabTerminalProps {
  sessionId?: string;
}

/**
 * Browser terminal that connects to the lab WebSocket session.
 * Uses a scrollable <div> for output and a hidden <input> to capture
 * keystrokes — no xterm.js dependency required.
 *
 * WebSocket URL: ws(s)://<host>/ws/labs/{sessionId}/term
 */
export function LabTerminal({ sessionId }: LabTerminalProps): JSX.Element {
  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  /** Append a line of text to the visible output area. */
  const appendOutput = useCallback((text: string) => {
    const el = outputRef.current;
    if (!el) return;
    const span = document.createElement("span");
    // Preserve raw terminal text; newlines become <br> via white-space:pre
    span.textContent = text;
    el.appendChild(span);
    el.scrollTop = el.scrollHeight;
  }, []);

  useEffect(() => {
    if (!sessionId) return;

    // Clear previous output when a new session starts
    if (outputRef.current) {
      outputRef.current.textContent = "";
    }

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/labs/${sessionId}/term`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      appendOutput("\r\n\x1b[32mConnected to lab terminal.\x1b[0m\r\n");
      // Focus the hidden input so keystrokes are captured immediately
      inputRef.current?.focus();
    };

    ws.onmessage = (event: MessageEvent) => {
      appendOutput(String(event.data));
    };

    ws.onerror = () => {
      appendOutput("\r\n\x1b[31m[error] WebSocket connection error.\x1b[0m\r\n");
    };

    ws.onclose = (event: CloseEvent) => {
      appendOutput(
        `\r\n\x1b[33m[disconnected] Session closed (code ${event.code}).\x1b[0m\r\n`,
      );
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [sessionId, appendOutput]);

  /** Forward keystroke data to the server. */
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;

      // Map common special keys to their ANSI sequences
      const specialKeys: Record<string, string> = {
        Enter: "\r",
        Backspace: "\x7f",
        Tab: "\t",
        ArrowUp: "\x1b[A",
        ArrowDown: "\x1b[B",
        ArrowRight: "\x1b[C",
        ArrowLeft: "\x1b[D",
        Escape: "\x1b",
      };

      if (e.key in specialKeys) {
        e.preventDefault();
        ws.send(specialKeys[e.key]);
        return;
      }

      // Ctrl+<letter> sequences
      if (e.ctrlKey && e.key.length === 1) {
        e.preventDefault();
        const code = e.key.toLowerCase().charCodeAt(0) - 96;
        if (code > 0 && code < 32) {
          ws.send(String.fromCharCode(code));
        }
        return;
      }

      // Printable characters are handled by onInput to avoid duplicates
    },
    [],
  );

  const handleInput = useCallback(
    (e: React.FormEvent<HTMLInputElement>) => {
      const ws = wsRef.current;
      const input = e.currentTarget;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      // Send whatever was just typed and clear the hidden input buffer
      if (input.value) {
        ws.send(input.value);
        input.value = "";
      }
    },
    [],
  );

  return (
    <div
      className="relative h-72 w-full overflow-hidden rounded-lg bg-slate-950 font-mono text-xs text-emerald-300"
      aria-label="lab-terminal"
      role="region"
      onClick={() => inputRef.current?.focus()}
    >
      {/* Scrollable output area */}
      <div
        ref={outputRef}
        className="h-full w-full overflow-auto p-4 whitespace-pre"
        aria-live="polite"
        aria-label="terminal output"
      >
        {!sessionId && "[cyberpath] no active lab session"}
      </div>

      {/* Hidden input captures keystrokes; visually off-screen */}
      <input
        ref={inputRef}
        type="text"
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        aria-hidden="true"
        tabIndex={sessionId ? 0 : -1}
        onKeyDown={handleKeyDown}
        onInput={handleInput}
        className="absolute -left-[9999px] top-0 opacity-0"
      />
    </div>
  );
}
