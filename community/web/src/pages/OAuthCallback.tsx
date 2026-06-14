import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useAuthStore } from "@/state/auth";

interface JWTPayload {
  sub: string;
  role: string;
  exp: number;
}

function parseJWTPayload(token: string): JWTPayload {
  const base64 = token.split(".")[1];
  // Pad the base64 string to a multiple of 4 characters.
  const padded = base64.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "=",
  );
  return JSON.parse(atob(padded)) as JWTPayload;
}

export default function OAuthCallback() {
  const navigate = useNavigate();
  const { login: storeLogin } = useAuthStore();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const err = params.get("error");

    if (err) {
      setError(decodeURIComponent(err));
      return;
    }

    if (token) {
      try {
        const payload = parseJWTPayload(token);
        storeLogin(token, payload.role, payload.sub, true);
        navigate("/", { replace: true });
      } catch {
        setError("Invalid token received. Please try signing in again.");
      }
      return;
    }

    setError("No token or error received. Please try signing in again.");
  }, [navigate, storeLogin]);

  if (error) {
    return (
      <div className="max-w-sm mx-auto mt-16">
        <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-8 text-center">
          <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100 mb-4">Sign-in failed</h1>
          <p className="text-sm text-red-600 dark:text-red-400 mb-6">{error}</p>
          <Link
            to="/login"
            className="text-sm text-brand hover:underline"
          >
            Back to login
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-sm mx-auto mt-16">
      <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-8 text-center">
        <p className="text-sm text-gray-500 dark:text-gray-400">Signing you in…</p>
      </div>
    </div>
  );
}
