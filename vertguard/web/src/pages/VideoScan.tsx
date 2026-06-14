import { useState, useEffect, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { getToken } from "../lib/auth";
import VerdictBadge from "../components/VerdictBadge";

// ── API shapes ────────────────────────────────────────────────────────

const SessionResponse = z.object({ session_id: z.string() });

const FrameScore = z.object({
  frame_seq: z.number(),
  confidence: z.number().optional().default(0),
  verdict: z.enum(["CLEAN", "SUSPICIOUS", "BLOCKED", "UNAVAILABLE"]),
  latency_ms: z.number().optional().default(0),
});
type FrameScore = z.infer<typeof FrameScore>;

// ── Helpers ───────────────────────────────────────────────────────────

/** Generates a random 512-dim CLIP embedding as base64 float32 bytes. */
function randomFeatureVector(): string {
  const dims = 512;
  const buf = new Float32Array(dims);
  for (let i = 0; i < dims; i++) {
    buf[i] = Math.random() * 2 - 1; // uniform [-1, 1]
  }
  const bytes = new Uint8Array(buf.buffer);
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

function verdictColor(verdict: string): string {
  switch (verdict) {
    case "BLOCKED":
      return "text-rose-400";
    case "SUSPICIOUS":
      return "text-amber-400";
    case "UNAVAILABLE":
      return "text-slate-500";
    default:
      return "text-emerald-400";
  }
}

function confidenceBarColor(verdict: string): string {
  switch (verdict) {
    case "BLOCKED":
      return "bg-rose-500";
    case "SUSPICIOUS":
      return "bg-amber-500";
    case "UNAVAILABLE":
      return "bg-slate-600";
    default:
      return "bg-emerald-500";
  }
}

// Build a WebSocket URL from the current page origin.
function wsURL(sessionID: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const base =
    (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
    `${proto}://${window.location.host}`;
  // Strip http(s):// prefix if VITE_API_BASE_URL is set with http scheme.
  const wsBase = base.replace(/^https?:\/\//, `${proto}://`);
  return `${wsBase}/api/v1/video/stream/${sessionID}`;
}

// ── Component ─────────────────────────────────────────────────────────

const MAX_HISTORY = 10;
const FRAME_INTERVAL_MS = 500;

type Status = "idle" | "connecting" | "live" | "error" | "stopped";

export default function VideoScan() {
  const { t } = useTranslation();
  const [sessionID, setSessionID] = useState<string | null>(null);
  const [status, setStatus] = useState<Status>("idle");
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<FrameScore[]>([]);
  const [frameSeq, setFrameSeq] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const frameSeqRef = useRef(0);

  // Keep frameSeqRef in sync so the interval closure always sees the
  // latest value without causing a re-render every tick.
  useEffect(() => {
    frameSeqRef.current = frameSeq;
  }, [frameSeq]);

  const stopSession = useCallback(() => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStatus("stopped");
  }, []);

  // Cleanup on unmount.
  useEffect(() => () => stopSession(), [stopSession]);

  const startSession = useCallback(async () => {
    setError(null);
    setHistory([]);
    setFrameSeq(0);
    frameSeqRef.current = 0;
    setStatus("connecting");

    try {
      // 1. Create a server-side session.
      const token = getToken();
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (token) headers["Authorization"] = `Bearer ${token}`;

      const resp = await fetch("/api/v1/video/session", { method: "POST", headers });
      if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`${resp.status}: ${body}`);
      }
      const parsed = SessionResponse.parse(await resp.json());
      setSessionID(parsed.session_id);

      // 2. Open WebSocket.
      const ws = new WebSocket(wsURL(parsed.session_id));
      wsRef.current = ws;

      ws.onopen = () => setStatus("live");
      ws.onerror = () => {
        setError(t("video:errors.ws_error"));
        setStatus("error");
        stopSession();
      };
      ws.onclose = () => {
        if (status !== "error") setStatus("stopped");
      };
      ws.onmessage = (ev) => {
        try {
          const score = FrameScore.parse(JSON.parse(ev.data as string));
          setHistory((prev) => [score, ...prev].slice(0, MAX_HISTORY));
        } catch {
          // Malformed server message — ignore.
        }
      };

      // 3. Start mock frame sender every 500 ms.
      timerRef.current = setInterval(() => {
        if (ws.readyState !== WebSocket.OPEN) return;
        const seq = frameSeqRef.current + 1;
        frameSeqRef.current = seq;
        setFrameSeq(seq);
        ws.send(
          JSON.stringify({
            frame_seq: seq,
            feature_vector: randomFeatureVector(),
            face_detected: true,
          })
        );
      }, FRAME_INTERVAL_MS);
    } catch (err) {
      setError(String(err));
      setStatus("error");
    }
  }, [t, stopSession, status]);

  // Derive a dominant verdict from the rolling history for the status
  // indicator (worst-case across the last 10 frames).
  const dominantVerdict = (() => {
    if (history.length === 0) return null;
    if (history.some((f) => f.verdict === "BLOCKED")) return "BLOCKED";
    if (history.some((f) => f.verdict === "SUSPICIOUS")) return "SUSPICIOUS";
    if (history.every((f) => f.verdict === "UNAVAILABLE")) return "UNAVAILABLE";
    return "CLEAN";
  })();

  const isRunning = status === "live" || status === "connecting";

  return (
    <div className="max-w-3xl">
      <h1 className="text-2xl font-semibold mb-2">{t("video:title")}</h1>
      <p className="text-slate-400 text-sm mb-6">{t("video:description")}</p>

      {/* Session info + controls */}
      <div className="flex items-center gap-4 mb-6">
        <button
          onClick={isRunning ? stopSession : startSession}
          className={`rounded px-4 py-1.5 text-sm font-medium ${
            isRunning
              ? "bg-rose-600 hover:bg-rose-500"
              : "bg-indigo-500 hover:bg-indigo-400"
          }`}
        >
          {isRunning ? t("video:stop_session") : t("video:start_session")}
        </button>

        {sessionID && (
          <span className="text-xs text-slate-500 font-mono truncate">
            {t("video:session_id_label")} {sessionID}
          </span>
        )}

        {/* Status indicator dot */}
        <span
          className={`ml-auto text-xs font-medium ${
            status === "live"
              ? "text-emerald-400"
              : status === "connecting"
              ? "text-amber-400"
              : status === "error"
              ? "text-rose-400"
              : "text-slate-500"
          }`}
        >
          {t(`video:status.${status}`)}
        </span>
      </div>

      {/* Dominant verdict badge */}
      {dominantVerdict && dominantVerdict !== "UNAVAILABLE" && (
        <div className="mb-4">
          <VerdictBadge verdict={dominantVerdict as "CLEAN" | "SUSPICIOUS" | "BLOCKED"} />
        </div>
      )}

      {/* Error message */}
      {error && <p className="text-rose-400 text-sm mb-4">{error}</p>}

      {/* Frame history table */}
      {history.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded p-4">
          <p className="text-xs text-slate-500 mb-3">
            {t("video:last_frames", { count: history.length })}
          </p>
          <table className="w-full text-xs">
            <thead className="text-slate-500">
              <tr>
                <th className="text-left py-1 pr-3">{t("video:table.frame")}</th>
                <th className="text-left py-1 pr-3">{t("video:table.verdict")}</th>
                <th className="text-left py-1 pr-3">{t("video:table.confidence")}</th>
                <th className="text-right py-1">{t("video:table.latency")}</th>
              </tr>
            </thead>
            <tbody>
              {history.map((f) => (
                <tr key={f.frame_seq} className="border-t border-slate-800">
                  <td className="py-1 pr-3 font-mono text-slate-300">#{f.frame_seq}</td>
                  <td className={`py-1 pr-3 font-medium ${verdictColor(f.verdict)}`}>
                    {f.verdict}
                  </td>
                  <td className="py-1 pr-3 w-40">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 bg-slate-800 rounded h-1.5 overflow-hidden">
                        <div
                          className={`h-full rounded ${confidenceBarColor(f.verdict)}`}
                          style={{ width: `${Math.min(f.confidence * 100, 100).toFixed(1)}%` }}
                        />
                      </div>
                      <span className="text-slate-400 w-10 text-right">
                        {(f.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                  </td>
                  <td className="py-1 text-right text-slate-400">
                    {f.latency_ms.toFixed(1)} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {status === "live" && history.length === 0 && (
        <p className="text-slate-500 text-sm">{t("video:waiting_frames")}</p>
      )}
    </div>
  );
}
