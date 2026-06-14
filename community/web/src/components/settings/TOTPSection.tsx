import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { setupTOTP, confirmTOTP, disableTOTP, getTOTPStatus } from "@/api/totp";
import { useAuthStore } from "@/state/auth";

export default function TOTPSection() {
  const { token } = useAuthStore();

  const { data: totpStatus, refetch: refetchTOTP } = useQuery({
    queryKey: ["totp-status"],
    queryFn: getTOTPStatus,
    enabled: !!token,
  });
  const totpEnabled = totpStatus?.enabled ?? false;

  const [totpSetupOpen, setTotpSetupOpen] = useState(false);
  const [totpSetupSecret, setTotpSetupSecret] = useState("");
  const [totpSetupQRUrl, setTotpSetupQRUrl] = useState("");
  const [totpSetupCode, setTotpSetupCode] = useState("");
  const [totpSetupError, setTotpSetupError] = useState<string | null>(null);
  const [totpSetupLoading, setTotpSetupLoading] = useState(false);

  const [totpDisableOpen, setTotpDisableOpen] = useState(false);
  const [totpDisableCode, setTotpDisableCode] = useState("");
  const [totpDisableError, setTotpDisableError] = useState<string | null>(null);
  const [totpDisableLoading, setTotpDisableLoading] = useState(false);

  const otpInputCls =
    "w-full border border-gray-300 dark:border-gray-700 rounded-md px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder:text-gray-400 font-mono tracking-widest text-center focus:outline-none focus:ring-2 focus:ring-brand/50";

  async function handleStartTOTPSetup() {
    setTotpSetupError(null);
    setTotpSetupLoading(true);
    try {
      const data = await setupTOTP();
      setTotpSetupSecret(data.secret);
      setTotpSetupQRUrl(data.qr_url);
      setTotpSetupCode("");
      setTotpSetupOpen(true);
    } catch {
      setTotpSetupError("Failed to start 2FA setup. Please try again.");
    } finally {
      setTotpSetupLoading(false);
    }
  }

  async function handleConfirmTOTP(e: React.FormEvent) {
    e.preventDefault();
    setTotpSetupError(null);
    setTotpSetupLoading(true);
    try {
      await confirmTOTP(totpSetupSecret, totpSetupCode);
      setTotpSetupOpen(false);
      setTotpSetupSecret("");
      setTotpSetupQRUrl("");
      setTotpSetupCode("");
      await refetchTOTP();
    } catch {
      setTotpSetupError("Invalid code. Please check your authenticator app and try again.");
    } finally {
      setTotpSetupLoading(false);
    }
  }

  async function handleDisableTOTP(e: React.FormEvent) {
    e.preventDefault();
    setTotpDisableError(null);
    setTotpDisableLoading(true);
    try {
      await disableTOTP(totpDisableCode);
      setTotpDisableOpen(false);
      setTotpDisableCode("");
      await refetchTOTP();
    } catch {
      setTotpDisableError("Invalid code. Please check your authenticator app and try again.");
    } finally {
      setTotpDisableLoading(false);
    }
  }

  return (
    <div className="mt-10 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
      <h2 className="font-semibold mb-1">Two-Factor Authentication</h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Protect your account with a time-based one-time password (TOTP) authenticator app.
      </p>

      {totpEnabled ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-green-600 dark:text-green-400">
            <svg className="w-5 h-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <span className="text-sm font-medium">2FA is enabled</span>
          </div>

          {!totpDisableOpen ? (
            <button
              onClick={() => { setTotpDisableOpen(true); setTotpDisableCode(""); setTotpDisableError(null); }}
              className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-300 text-sm rounded-md hover:bg-gray-50 dark:hover:bg-gray-800"
            >
              Disable 2FA
            </button>
          ) : (
            <form onSubmit={handleDisableTOTP} className="space-y-3 max-w-xs">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Enter your current 6-digit code to confirm:
              </p>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                maxLength={6}
                value={totpDisableCode}
                onChange={(e) => setTotpDisableCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
                required
                autoFocus
                className={otpInputCls}
              />
              {totpDisableError && <p className="text-xs text-red-500">{totpDisableError}</p>}
              <div className="flex gap-2">
                <button
                  type="submit"
                  disabled={totpDisableLoading || totpDisableCode.length !== 6}
                  className="px-4 py-2 bg-red-600 text-white text-sm rounded-md hover:bg-red-700 disabled:opacity-50"
                >
                  {totpDisableLoading ? "Disabling…" : "Confirm disable"}
                </button>
                <button
                  type="button"
                  onClick={() => { setTotpDisableOpen(false); setTotpDisableCode(""); setTotpDisableError(null); }}
                  className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 text-sm rounded-md hover:bg-gray-50 dark:hover:bg-gray-800"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            2FA is not enabled. Add an extra layer of security to your account.
          </p>

          {!totpSetupOpen ? (
            <button
              onClick={handleStartTOTPSetup}
              disabled={totpSetupLoading}
              className="px-4 py-2 bg-brand text-white text-sm rounded-md hover:opacity-90 disabled:opacity-50"
            >
              {totpSetupLoading ? "Loading…" : "Enable 2FA"}
            </button>
          ) : (
            <div className="space-y-4 max-w-sm">
              <p className="text-sm text-gray-600 dark:text-gray-400">
                Scan the QR code with your authenticator app (e.g. Google Authenticator, Authy), then enter the 6-digit code to confirm.
              </p>
              <div className="flex justify-center">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(totpSetupQRUrl)}&size=200x200`}
                  alt="TOTP QR code"
                  width={200}
                  height={200}
                  className="rounded border border-gray-200 dark:border-gray-700"
                />
              </div>
              <div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Or enter this key manually:</p>
                <code className="block w-full bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded px-3 py-2 text-xs font-mono break-all select-all text-gray-800 dark:text-gray-200">
                  {totpSetupSecret}
                </code>
              </div>
              <form onSubmit={handleConfirmTOTP} className="space-y-3">
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={totpSetupCode}
                  onChange={(e) => setTotpSetupCode(e.target.value.replace(/\D/g, ""))}
                  placeholder="000000"
                  required
                  autoFocus
                  className={otpInputCls}
                />
                {totpSetupError && <p className="text-xs text-red-500">{totpSetupError}</p>}
                <div className="flex gap-2">
                  <button
                    type="submit"
                    disabled={totpSetupLoading || totpSetupCode.length !== 6}
                    className="px-4 py-2 bg-brand text-white text-sm rounded-md hover:opacity-90 disabled:opacity-50"
                  >
                    {totpSetupLoading ? "Verifying…" : "Verify & Enable"}
                  </button>
                  <button
                    type="button"
                    onClick={() => { setTotpSetupOpen(false); setTotpSetupSecret(""); setTotpSetupQRUrl(""); setTotpSetupCode(""); setTotpSetupError(null); }}
                    className="px-4 py-2 border border-gray-300 dark:border-gray-700 text-gray-600 dark:text-gray-400 text-sm rounded-md hover:bg-gray-50 dark:hover:bg-gray-800"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
