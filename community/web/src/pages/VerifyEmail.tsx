// Route: add <Route path="verify-email" element={<VerifyEmail />} /> to App.tsx public routes

import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { verifyEmail, resendVerification } from "@/api/auth";
import { useAuthStore } from "@/state/auth";

type Status = "verifying" | "success" | "error";

export default function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const { setEmailVerified } = useAuthStore();

  const [status, setStatus] = useState<Status>("verifying");

  // Resend state
  const [resendLabel, setResendLabel] = useState("Resend verification email");
  const [resendDisabled, setResendDisabled] = useState(false);

  useEffect(() => {
    if (!token) {
      setStatus("error");
      return;
    }

    verifyEmail(token)
      .then(() => {
        setEmailVerified(true);
        setStatus("success");
      })
      .catch(() => {
        setStatus("error");
      });
  }, [token, setEmailVerified]);

  async function handleResend() {
    if (resendDisabled) return;
    setResendDisabled(true);
    setResendLabel("Sent!");
    try {
      await resendVerification();
    } catch {
      // Silently ignore — user may not be logged in.
    }
    // Re-enable button after 60 seconds.
    setTimeout(() => {
      setResendLabel("Resend verification email");
      setResendDisabled(false);
    }, 60_000);
  }

  if (status === "verifying") {
    return (
      <div className="max-w-sm mx-auto mt-20 text-center text-gray-600">
        <p className="text-sm">Verifying your email address…</p>
      </div>
    );
  }

  if (status === "success") {
    return (
      <div className="max-w-sm mx-auto mt-20 text-center">
        <div className="bg-green-50 border border-green-200 rounded-lg p-8">
          <h1 className="text-lg font-semibold text-green-800 mb-2">Email verified!</h1>
          <p className="text-sm text-green-700 mb-4">
            Your email address has been verified. You can now use all features.
          </p>
          <Link to="/" className="text-sm text-brand hover:underline">
            Go to home
          </Link>
        </div>
      </div>
    );
  }

  // error
  return (
    <div className="max-w-sm mx-auto mt-20 text-center">
      <div className="bg-red-50 border border-red-200 rounded-lg p-8">
        <h1 className="text-lg font-semibold text-red-800 mb-2">Link invalid or expired</h1>
        <p className="text-sm text-red-700 mb-4">
          This verification link is invalid or has expired.
        </p>
        <button
          onClick={handleResend}
          disabled={resendDisabled}
          className="text-sm text-brand hover:underline disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {resendLabel}
        </button>
      </div>
    </div>
  );
}
