import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { register, getAuthMethods } from "@/api/auth";
import type { AuthMethods } from "@/api/auth";
import { useAuthStore } from "@/state/auth";

const DEFAULT_METHODS: AuthMethods = {
  sinauth: true,
  sinauth_primary: true,
  native: true,
  github: true,
  google: false,
};

export default function Register() {
  const navigate = useNavigate();

  const [methods, setMethods] = useState<AuthMethods>(DEFAULT_METHODS);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [inviteCode, setInviteCode] = useState("");

  const [errors, setErrors] = useState<{
    username?: string;
    email?: string;
    password?: string;
    invite_code?: string;
    banner?: string;
  }>({});

  const [loading, setLoading] = useState(false);
  const [rateLimitCountdown, setRateLimitCountdown] = useState(0);
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

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setErrors({});
    setLoading(true);

    try {
      const data = await register({
        username,
        email,
        password,
        invite_code: inviteCode || undefined,
      });
      useAuthStore.getState().login(data.token, data.role, data.sub, data.email_verified ?? false);
      const destination =
        localStorage.getItem("onboarding_completed") === "true" ? "/" : "/onboarding";
      navigate(destination);
    } catch (err: unknown) {
      const status = (err as { response?: { status?: number; data?: { error?: string } } })
        ?.response?.status;
      const message =
        (err as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "";

      if (status === 429) {
        const retryAfter = (err as { retryAfter?: number | null }).retryAfter ?? null;
        const bannerMsg = retryAfter
          ? `Too many attempts. Please try again in ${retryAfter} seconds.`
          : "Too many attempts. Please try again in a moment.";
        setErrors({ banner: bannerMsg });
        if (retryAfter) startCountdown(retryAfter);
      } else if (status === 400 && message === "invite code required") {
        setErrors({ invite_code: "An invite code is required to register." });
      } else if (status === 400 && message === "invite code not found") {
        setErrors({ invite_code: "Invite code not found." });
      } else if (status === 400 && message === "invite code expired") {
        setErrors({ invite_code: "This invite code has expired." });
      } else if (status === 409 && message === "invite code already used") {
        setErrors({ invite_code: "This invite code has already been used." });
      } else if (status === 409) {
        setErrors({ banner: "Username or email already taken." });
      } else if (status === 403) {
        setErrors({ email: "Email domain not allowed on this platform." });
      } else {
        setErrors({ banner: "Something went wrong. Please try again." });
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-12">
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-sm p-8">
        <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-6">Create an account</h1>

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

        {methods.github && (
          <a
            href="/api/v1/auth/github"
            className="mt-3 flex items-center justify-center gap-2 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors text-sm text-gray-800 dark:text-gray-200"
          >
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
            </svg>
            Continue with GitHub
          </a>
        )}

        {!methods.native && (
          <p className="mt-4 text-center text-xs text-gray-400 dark:text-gray-500">
            One SIN account works across every platform in the ecosystem.
          </p>
        )}

        {methods.native && (
        <>
        <div className="relative my-5">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-200 dark:border-gray-700" />
          </div>
          <div className="relative flex justify-center text-xs text-gray-400 dark:text-gray-500">
            <span className="bg-white dark:bg-gray-900 px-2">or create a local account</span>
          </div>
        </div>

        {errors.banner && (
          <div className="mb-4 rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">
            {errors.banner}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              required
              autoComplete="username"
              className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            {errors.username && (
              <p className="mt-1 text-xs text-red-600">{errors.username}</p>
            )}
          </div>

          <div>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email address"
              required
              autoComplete="email"
              className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            {errors.email && (
              <p className="mt-1 text-xs text-red-600">{errors.email}</p>
            )}
          </div>

          <div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
              autoComplete="new-password"
              className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            {errors.password && (
              <p className="mt-1 text-xs text-red-600">{errors.password}</p>
            )}
          </div>

          <div>
            <input
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder="Invite code (if required)"
              autoComplete="off"
              className="w-full border border-gray-300 dark:border-gray-700 rounded-lg px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 dark:placeholder:text-gray-500 focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            {errors.invite_code && (
              <p className="mt-1 text-xs text-red-600">{errors.invite_code}</p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || rateLimitCountdown > 0}
            className="w-full py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
          >
            {loading ? "Creating account…" : rateLimitCountdown > 0 ? `Try again in ${rateLimitCountdown}s` : "Create account"}
          </button>
        </form>
        </>
        )}

        <p className="mt-6 text-center text-sm text-gray-500 dark:text-gray-400">
          Already have an account?{" "}
          <Link to="/login" className="text-brand hover:underline">
            Log in
          </Link>
        </p>
      </div>
    </div>
  );
}
