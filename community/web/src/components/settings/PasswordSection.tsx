import { useState } from "react";
import { changePassword } from "@/api/auth";

export default function PasswordSection() {
  const [pwForm, setPwForm] = useState({ current: "", next: "", confirm: "" });
  const [pwSaving, setPwSaving] = useState(false);
  const [pwSuccess, setPwSuccess] = useState(false);
  const [pwError, setPwError] = useState<string | null>(null);

  const inputCls =
    "w-full border border-gray-300 dark:border-gray-700 rounded-md px-3 py-2 text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-brand/50";

  async function handleChangePassword(e: React.FormEvent) {
    e.preventDefault();
    setPwError(null);
    setPwSuccess(false);
    if (pwForm.next !== pwForm.confirm) {
      setPwError("New passwords do not match.");
      return;
    }
    setPwSaving(true);
    try {
      await changePassword(pwForm.current, pwForm.next);
      setPwForm({ current: "", next: "", confirm: "" });
      setPwSuccess(true);
      setTimeout(() => setPwSuccess(false), 4000);
    } catch (err: unknown) {
      setPwError(err instanceof Error ? err.message : "Failed to update password.");
    } finally {
      setPwSaving(false);
    }
  }

  return (
    <div className="mt-6 bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
      <h2 className="font-semibold mb-1">Change Password</h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Update the password you use to sign in.
      </p>
      <form onSubmit={handleChangePassword} className="space-y-4 max-w-sm">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="pw_current">
            Current password
          </label>
          <input
            id="pw_current"
            type="password"
            autoComplete="current-password"
            value={pwForm.current}
            onChange={(e) => setPwForm((p) => ({ ...p, current: e.target.value }))}
            required
            className={inputCls}
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="pw_new">
            New password
          </label>
          <input
            id="pw_new"
            type="password"
            autoComplete="new-password"
            value={pwForm.next}
            onChange={(e) => setPwForm((p) => ({ ...p, next: e.target.value }))}
            required
            className={inputCls}
          />
          <p className="mt-1 text-xs text-gray-400 dark:text-gray-500">Minimum 8 characters</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="pw_confirm">
            Confirm new password
          </label>
          <input
            id="pw_confirm"
            type="password"
            autoComplete="new-password"
            value={pwForm.confirm}
            onChange={(e) => setPwForm((p) => ({ ...p, confirm: e.target.value }))}
            required
            className={inputCls}
          />
        </div>
        {pwError && <p className="text-sm text-red-500">{pwError}</p>}
        {pwSuccess && <p className="text-sm text-green-600">Password updated successfully</p>}
        <button
          type="submit"
          disabled={pwSaving}
          className="px-4 py-2 bg-brand text-white text-sm rounded-md hover:opacity-90 disabled:opacity-50"
        >
          {pwSaving ? "Updating…" : "Update password"}
        </button>
      </form>
    </div>
  );
}
