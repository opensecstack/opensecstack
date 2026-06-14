import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { BookOpen, Boxes, ShieldCheck } from "lucide-react";
import { loginWithPopup, decodeJWT } from "@/lib/sinauth";
import { useAuth, type AuthUser } from "@/state/auth";

const features = [
  {
    icon: Boxes,
    title: "Isolated hands-on labs",
    body: "Practice in disposable, Docker- and Wasm-isolated lab environments that spin up on demand and reset cleanly when you are done.",
  },
  {
    icon: BookOpen,
    title: "Guided learning paths",
    body: "Follow structured learning paths and skill tracks that take you from fundamentals to advanced offensive and defensive security.",
  },
  {
    icon: ShieldCheck,
    title: "Verifiable training records",
    body: "Completed lessons and labs produce training records that feed directly into NIS2 Compass and CITADEL for compliance reporting.",
  },
];

export default function Landing(): JSX.Element {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function handleSignIn(): Promise<void> {
    setPending(true);
    setError(null);
    try {
      const tokens = await loginWithPopup();
      const payload = decodeJWT(tokens.access_token);
      const user: AuthUser = {
        id: (payload.sub as string) ?? "",
        email: (payload.email as string) ?? "",
        display_name: (payload.name as string) ?? (payload.email as string) ?? "",
        locale: "en",
        role: (payload.role as AuthUser["role"]) ?? "learner",
      };
      login(user, tokens);
      navigate("/tracks", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setPending(false);
    }
  }

  return (
    <div className="flex min-h-screen flex-col bg-white text-slate-900">
      <header className="border-b border-slate-200">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <span className="flex items-center gap-2 text-lg font-bold text-brand">
            <ShieldCheck className="h-6 w-6" aria-hidden="true" />
            CyberPath
          </span>
          <button
            onClick={handleSignIn}
            disabled={pending}
            className="rounded-md bg-brand px-4 py-2 text-sm font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
          >
            {pending ? "Opening…" : "Sign in"}
          </button>
        </div>
      </header>

      <main className="flex-1">
        <section className="mx-auto max-w-6xl px-4 py-20 text-center sm:py-28">
          <h1 className="text-4xl font-extrabold tracking-tight text-slate-900 sm:text-6xl">
            CyberPath
          </h1>
          <p className="mt-4 text-xl font-semibold text-brand sm:text-2xl">
            Hands-on Security Training
          </p>
          <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-600">
            Build real cybersecurity skills in isolated, hands-on lab environments. Follow guided
            learning paths and earn verifiable training records that plug into your wider compliance
            stack.
          </p>
          {error && (
            <p className="mx-auto mt-6 max-w-md rounded bg-red-50 p-2 text-sm text-red-600">
              {error}
            </p>
          )}
          <div className="mt-10 flex justify-center">
            <button
              onClick={handleSignIn}
              disabled={pending}
              className="rounded-md bg-brand px-6 py-3 text-base font-semibold text-white transition hover:bg-blue-700 disabled:opacity-60"
            >
              {pending ? "Opening…" : "Sign in to get started"}
            </button>
          </div>
        </section>

        <section className="border-t border-slate-200 bg-slate-50">
          <div className="mx-auto grid max-w-6xl gap-8 px-4 py-16 md:grid-cols-3">
            {features.map(({ icon: Icon, title, body }) => (
              <div
                key={title}
                className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm"
              >
                <Icon className="h-8 w-8 text-brand" aria-hidden="true" />
                <h3 className="mt-4 text-lg font-semibold text-slate-900">{title}</h3>
                <p className="mt-2 text-sm text-slate-600">{body}</p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto max-w-6xl px-4 py-6 text-center text-xs text-slate-500">
          Part of the SIN ecosystem.
        </div>
      </footer>
    </div>
  );
}
