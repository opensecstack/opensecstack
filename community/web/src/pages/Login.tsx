import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { login, getAuthMethods } from "@/api/auth";
import { apiClient } from "@/api/client";
import { useAuthStore } from "@/state/auth";
import type { LoginResponse, AuthMethods } from "@/api/auth";

type Step = "credentials" | "totp";

// Default while methods are loading: SIN-first, native available.
const DEFAULT_METHODS: AuthMethods = {
  sinauth: true,
  sinauth_primary: true,
  native: true,
  github: true,
  google: false,
};

export default function Login() {
  const navigate = useNavigate();
  const { login: storeLogin } = useAuthStore();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [step, setStep] = useState<Step>("credentials");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [rateLimitCountdown, setRateLimitCountdown] = useState(0);
  const [methods, setMethods] = useState<AuthMethods>(DEFAULT_METHODS);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    getAuthMethods().then(setMethods).catch(() => setMethods(DEFAULT_METHODS));
    return () => {
      if (countdownRef.current) clearInterval(countdownRef.current);
    };
  }, []);

  function startCountdown(seconds: number) {
    setRateLimitCountdown(seconds);
    if (countdownRef.current) clearInterval(countdownRef.current);
    countdownRef.current = setInterval(() => {
      setRateLimitCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(countdownRef.current!);
          countdownRef.current = null;
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
  }

  async function handleCredentials(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await login(username, password);
      // Server returns { require_totp: true } when TOTP is enabled but no code was provided.
      if ((data as unknown as { require_totp?: boolean }).require_totp) {
        setStep("totp");
        return;
      }
      storeLogin((data as LoginResponse).token, (data as LoginResponse).role, (data as LoginResponse).sub, (data as LoginResponse).email_verified ?? false);
      navigate("/");
    } catch (err: unknown) {
      const e = err as { response?: { status?: number }; retryAfter?: number | null };
      if (e?.response?.status === 429) {
        const seconds = e.retryAfter ?? null;
        setError(
          seconds
            ? `Too many attempts. Please try again in ${seconds} seconds.`
            : "Too many attempts. Please try again in a moment."
        );
        if (seconds) startCountdown(seconds);
      } else {
        setError("Invalid username or password.");
      }
    } finally {
      setLoading(false);
    }
  }

  async function handleTOTP(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await apiClient.post<LoginResponse>("/api/v1/auth/login", {
        username,
        password,
        totp_code: totpCode,
      });
      const data = res.data;
      storeLogin(data.token, data.role, data.sub, data.email_verified ?? false);
      navigate("/");
    } catch (err: unknown) {
      const e = err as { response?: { status?: number }; retryAfter?: number | null };
      if (e?.response?.status === 429) {
        const seconds = e.retryAfter ?? null;
        setError(
          seconds
            ? `Too many attempts. Please try again in ${seconds} seconds.`
            : "Too many attempts. Please try again in a moment."
        );
        if (seconds) startCountdown(seconds);
      } else {
        setError("Invalid authentication code. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }

  const inputClass =
    "w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40";

  return (
    <div className="max-w-sm mx-auto mt-16">
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-8">
        {step === "credentials" ? (
          <>
            <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6">Sign in to Community</h1>

            {methods.sinauth && (
              <a
                href="/api/v1/auth/sinauth"
                className="flex items-center justify-center gap-2 w-full px-4 py-2.5 bg-brand text-white rounded-lg hover:bg-brand-dark transition-colors text-sm font-medium"
              >
                <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2 4 6v6c0 5 3.4 8.5 8 10 4.6-1.5 8-5 8-10V6l-8-4z" strokeLinejoin="round" />
                </svg>
                Continue with SIN
              </a>
            )}

            {(methods.github || methods.google) && (
              <div className="mt-3 space-y-2">
                {methods.github && (
                  <a
                    href="/api/v1/auth/github"
                    className="flex items-center justify-center gap-2 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-sm text-gray-800 dark:text-gray-200"
                  >
                    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
                      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                    </svg>
                    Continue with GitHub
                  </a>
                )}
                {methods.google && (
                  <a
                    href="/api/v1/auth/google"
                    className="flex items-center justify-center gap-2 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-sm text-gray-800 dark:text-gray-200"
                  >
                    Continue with Google
                  </a>
                )}
              </div>
            )}

            {!methods.native && (
              <p className="mt-4 text-center text-xs text-gray-400 dark:text-gray-500">
                Your SIN account works across every platform in the ecosystem.
              </p>
            )}

            {methods.native && (
            <>
            <div className="relative my-5">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200 dark:border-gray-700" />
              </div>
              <div className="relative flex justify-center text-xs text-gray-400 dark:text-gray-500">
                <span className="bg-white dark:bg-gray-900 px-2">or use a local account</span>
              </div>
            </div>

            <form onSubmit={handleCredentials} className="space-y-4">
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Username"
                required
                className={inputClass}
              />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                required
                className={inputClass}
              />
              {error && <p className="text-sm text-red-600">{error}</p>}
              <button
                type="submit"
                disabled={loading || rateLimitCountdown > 0}
                className="w-full py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
              >
                {loading ? "Signing in…" : rateLimitCountdown > 0 ? `Try again in ${rateLimitCountdown}s` : "Sign in"}
              </button>
            </form>
            </>
            )}
          </>
        ) : (
          <>
            <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-2">Two-factor authentication</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
              Enter the 6-digit code from your authenticator app.
            </p>
            <form onSubmit={handleTOTP} className="space-y-4">
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
                required
                autoFocus
                className={inputClass + " tracking-widest text-center text-lg font-mono"}
              />
              {error && <p className="text-sm text-red-600">{error}</p>}
              <button
                type="submit"
                disabled={loading || totpCode.length !== 6 || rateLimitCountdown > 0}
                className="w-full py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
              >
                {loading ? "Verifying…" : rateLimitCountdown > 0 ? `Try again in ${rateLimitCountdown}s` : "Verify"}
              </button>
              <button
                type="button"
                onClick={() => { setStep("credentials"); setTotpCode(""); setError(""); }}
                className="w-full py-2 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
              >
                Back
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
