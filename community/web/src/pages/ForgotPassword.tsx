import { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { forgotPassword } from "@/api/auth";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [rateLimitCountdown, setRateLimitCountdown] = useState(0);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
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
    setError("");
    setLoading(true);
    try {
      await forgotPassword(email);
      setSubmitted(true);
    } catch (err: unknown) {
      const e2 = err as { response?: { status?: number }; retryAfter?: number | null };
      if (e2?.response?.status === 429) {
        const seconds = e2.retryAfter ?? null;
        setError(
          seconds
            ? `Too many attempts. Please try again in ${seconds} seconds.`
            : "Too many attempts. Please try again in a moment."
        );
        if (seconds) startCountdown(seconds);
      }
      // For other errors, stay silent (preserve existing UX: always show success to avoid email enumeration)
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-sm mx-auto mt-16">
      <div className="bg-white border border-gray-200 rounded-lg p-8">
        <h1 className="text-xl font-bold text-gray-900 mb-6">Reset your password</h1>

        {submitted ? (
          <div className="space-y-4">
            <p className="text-sm text-gray-700">
              If that email is registered, you'll receive a reset link shortly.
            </p>
            <Link
              to="/login"
              className="block text-sm text-center text-brand hover:underline"
            >
              Back to sign in
            </Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Your email address"
              required
              className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand/40"
            />
            {error && <p className="text-sm text-red-600">{error}</p>}
            <button
              type="submit"
              disabled={loading || rateLimitCountdown > 0}
              className="w-full py-2 bg-brand text-white text-sm rounded-lg hover:bg-brand-dark disabled:opacity-50 transition-colors"
            >
              {loading ? "Sending…" : rateLimitCountdown > 0 ? `Try again in ${rateLimitCountdown}s` : "Send reset link"}
            </button>
            <Link
              to="/login"
              className="block text-sm text-center text-gray-500 hover:underline"
            >
              Back to sign in
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}
