import { useEffect, useState } from "react";
import { apiClient } from "@/api/client";

export default function TotpSetup() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [step, setStep] = useState<"idle" | "setup" | "disable">("idle");
  const [secret, setSecret] = useState("");
  const [qrUrl, setQrUrl] = useState("");
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    apiClient
      .get("/api/v1/me/totp")
      .then((r) => setEnabled(r.data.enabled))
      .catch(() => setEnabled(false));
  }, []);

  const startSetup = async () => {
    setLoading(true);
    setError("");
    try {
      const r = await apiClient.post("/api/v1/me/totp/setup");
      setSecret(r.data.secret);
      setQrUrl(r.data.qr_url);
      setStep("setup");
    } catch {
      setError("Failed to start setup");
    } finally {
      setLoading(false);
    }
  };

  const confirm = async () => {
    if (code.length !== 6) {
      setError("Enter 6-digit code");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await apiClient.post("/api/v1/me/totp/confirm", { secret, code });
      setEnabled(true);
      setStep("idle");
      setCode("");
    } catch {
      setError("Invalid code. Try again.");
    } finally {
      setLoading(false);
    }
  };

  const disable = async () => {
    if (code.length !== 6) {
      setError("Enter 6-digit code");
      return;
    }
    setLoading(true);
    setError("");
    try {
      await apiClient.delete("/api/v1/me/totp", { data: { code } });
      setEnabled(false);
      setStep("idle");
      setCode("");
    } catch {
      setError("Invalid code.");
    } finally {
      setLoading(false);
    }
  };

  const cancel = () => {
    setStep("idle");
    setCode("");
    setError("");
  };

  if (enabled === null)
    return <div className="text-sm text-gray-500">Loading…</div>;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
            Two-factor authentication
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            {enabled
              ? "2FA is enabled on your account."
              : "Add an extra layer of security with an authenticator app."}
          </p>
        </div>
        <span
          className={`text-xs px-2 py-0.5 rounded-full font-medium ${
            enabled
              ? "bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400"
              : "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400"
          }`}
        >
          {enabled ? "Enabled" : "Disabled"}
        </span>
      </div>

      {step === "idle" && (
        <button
          onClick={() => (enabled ? setStep("disable") : startSetup())}
          disabled={loading}
          className="text-sm px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50"
        >
          {loading ? "Loading…" : enabled ? "Disable 2FA" : "Enable 2FA"}
        </button>
      )}

      {step === "setup" && (
        <div className="space-y-3 p-4 border border-gray-200 dark:border-gray-700 rounded-lg">
          <p className="text-sm text-gray-700 dark:text-gray-300">
            1. Scan this QR code with your authenticator app (Google
            Authenticator, Authy, etc.)
          </p>
          <img
            src={`https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encodeURIComponent(qrUrl)}`}
            alt="TOTP QR code"
            className="w-44 h-44 border rounded"
          />
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Or enter secret manually:{" "}
            <code className="font-mono bg-gray-100 dark:bg-gray-800 px-1 rounded">
              {secret}
            </code>
          </p>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            2. Enter the 6-digit code from your app:
          </p>
          <input
            value={code}
            onChange={(e) =>
              setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
            }
            placeholder="000000"
            maxLength={6}
            className="w-32 text-center text-xl font-mono border border-gray-300 dark:border-gray-600 rounded px-3 py-2 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
          />
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex gap-2">
            <button
              onClick={confirm}
              disabled={loading || code.length !== 6}
              className="text-sm px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white disabled:opacity-50"
            >
              {loading ? "Verifying…" : "Verify & Enable"}
            </button>
            <button
              onClick={cancel}
              className="text-sm px-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {step === "disable" && (
        <div className="space-y-3 p-4 border border-red-200 dark:border-red-800 rounded-lg">
          <p className="text-sm text-gray-700 dark:text-gray-300">
            Enter your current 6-digit code to disable 2FA:
          </p>
          <input
            value={code}
            onChange={(e) =>
              setCode(e.target.value.replace(/\D/g, "").slice(0, 6))
            }
            placeholder="000000"
            maxLength={6}
            className="w-32 text-center text-xl font-mono border border-gray-300 dark:border-gray-600 rounded px-3 py-2 bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
          />
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex gap-2">
            <button
              onClick={disable}
              disabled={loading || code.length !== 6}
              className="text-sm px-3 py-1.5 rounded bg-red-600 hover:bg-red-700 text-white disabled:opacity-50"
            >
              {loading ? "Disabling…" : "Disable 2FA"}
            </button>
            <button
              onClick={cancel}
              className="text-sm px-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
