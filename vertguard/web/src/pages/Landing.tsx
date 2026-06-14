import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, ScanText, FileCheck2, Crosshair } from "lucide-react";
import { loginWithPopup } from "../lib/sinauth";
import { setToken } from "../lib/auth";

const features = [
  {
    icon: ScanText,
    title: "Prompt-injection detection",
    body: "Detect prompt-injection, jailbreaks and LLM-abuse patterns before malicious input reaches your models or downstream tools.",
  },
  {
    icon: FileCheck2,
    title: "C2PA content provenance",
    body: "Verify the origin and integrity of media and documents using C2PA provenance signatures to spot tampered or synthetic content.",
  },
  {
    icon: Crosshair,
    title: "MITRE ATLAS coverage",
    body: "Map detections to MITRE ATLAS so your AI threat coverage is aligned with a recognised adversarial-ML knowledge base.",
  },
];

export default function Landing() {
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function handleSignIn(): Promise<void> {
    setPending(true);
    setError("");
    try {
      const tokens = await loginWithPopup();
      setToken(tokens.access_token);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <span className="flex items-center gap-2 text-lg font-semibold text-indigo-400">
            <Shield className="h-6 w-6" aria-hidden="true" />
            VertGuard
          </span>
          <button
            onClick={handleSignIn}
            disabled={pending}
            className="rounded bg-indigo-500 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-400 disabled:opacity-60"
          >
            {pending ? "Opening…" : "Sign in"}
          </button>
        </div>
      </header>

      <main className="flex-1">
        <section className="mx-auto max-w-6xl px-4 py-20 text-center sm:py-28">
          <h1 className="text-4xl font-extrabold tracking-tight sm:text-6xl">VertGuard</h1>
          <p className="mt-4 text-xl font-semibold text-indigo-400 sm:text-2xl">
            AI-Attack Defence
          </p>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-400">
            Defend your AI systems against adversarial attacks. VertGuard inspects prompts, content
            and media for abuse, injection and tampering, with detections aligned to industry threat
            frameworks.
          </p>
          {error && <p className="mt-6 text-sm text-rose-400">{error}</p>}
          <div className="mt-10 flex justify-center">
            <button
              onClick={handleSignIn}
              disabled={pending}
              className="rounded bg-indigo-500 px-6 py-3 text-base font-semibold text-white transition hover:bg-indigo-400 disabled:opacity-60"
            >
              {pending ? "Opening…" : "Sign in to get started"}
            </button>
          </div>
        </section>

        <section className="border-t border-slate-800 bg-slate-900">
          <div className="mx-auto grid max-w-6xl gap-8 px-4 py-16 md:grid-cols-3">
            {features.map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="rounded-lg border border-slate-800 bg-slate-950 p-6"
              >
                <Icon className="h-8 w-8 text-indigo-400" aria-hidden="true" />
                <h3 className="mt-4 text-lg font-semibold text-slate-100">{title}</h3>
                <p className="mt-2 text-sm text-slate-400">{body}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-800">
        <div className="mx-auto max-w-6xl px-4 py-6 text-center text-xs text-slate-500">
          Part of the SIN ecosystem.
        </div>
      </footer>
    </div>
  );
}
