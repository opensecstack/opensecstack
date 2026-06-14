import { Outlet, Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "@/state/auth";
import { useThemeStore } from "@/state/theme";
import { PenLine, LogOut, LogIn, Moon, Sun, Menu, X } from "lucide-react";
import { useState } from "react";
import NotificationBell from "@/components/NotificationBell";
import BroadcastBanner from "@/components/BroadcastBanner";
import Logo from "@/components/Logo";
import Sidebar from "@/components/Sidebar";
import KeyboardShortcutsModal from "@/components/KeyboardShortcutsModal";
import InstallPrompt from "@/components/InstallPrompt";
import BackToTop from "@/components/BackToTop";
import SearchAutocomplete from "@/components/SearchAutocomplete";
import { resendVerification } from "@/api/auth";
import { ErrorBoundary } from "@/components/ErrorBoundary";

export default function Layout() {
  const { token, username, emailVerified, logout } = useAuthStore();
  const { dark, toggle } = useThemeStore();
  const navigate = useNavigate();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Resend-verification banner state
  const [resendLabel, setResendLabel] = useState("Resend email");
  const [resendDisabled, setResendDisabled] = useState(false);

  function handleSearch(q: string) {
    if (q.trim()) navigate(`/search?q=${encodeURIComponent(q.trim())}`);
  }

  async function handleResend() {
    if (resendDisabled) return;
    setResendDisabled(true);
    setResendLabel("Sent!");
    try {
      await resendVerification();
    } catch {
      // Optimistic — user sees "Sent!" regardless; avoids leaking errors in the UI.
    }
    setTimeout(() => {
      setResendLabel("Resend email");
      setResendDisabled(false);
    }, 60_000);
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      <header className="sticky top-0 z-50 bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 shadow-sm">
        <div className="max-w-6xl mx-auto px-4 h-14 flex items-center gap-4">
          <Link to="/" className="shrink-0" aria-label="SIN Community">
            <Logo size={40} />
          </Link>
          <SearchAutocomplete onSearch={handleSearch} />
          <nav className="flex items-center gap-2 ml-auto">
            <button
              className="md:hidden p-1.5 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open menu"
            >
              <Menu className="w-5 h-5" />
            </button>
            <button
              onClick={toggle}
              aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
              className="p-1.5 rounded-lg text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
            >
              {dark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
            {token ? (
              <>
                <Link
                  to="/new"
                  className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-brand text-white rounded-lg hover:bg-brand-dark transition-colors"
                >
                  <PenLine className="w-4 h-4" /> Write
                </Link>
                <NotificationBell />
                <Link to={`/users/${username}`} className="text-sm text-gray-600 dark:text-gray-400 hover:text-brand">
                  {username}
                </Link>
                <button onClick={logout} className="text-gray-400 dark:text-gray-500 hover:text-red-500">
                  <LogOut className="w-4 h-4" />
                </button>
              </>
            ) : (
              <Link to="/login" className="flex items-center gap-1 text-sm text-gray-600 dark:text-gray-400 hover:text-brand">
                <LogIn className="w-4 h-4" /> Login
              </Link>
            )}
          </nav>
        </div>
      </header>

      {token && !emailVerified && (
        <div className="bg-yellow-50 border-b border-yellow-200 px-4 py-2 text-sm text-yellow-800 flex items-center justify-between">
          <span>Please verify your email address to unlock all features.</span>
          <button
            onClick={handleResend}
            disabled={resendDisabled}
            className="text-yellow-700 underline hover:text-yellow-900 ml-4 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {resendLabel}
          </button>
        </div>
      )}

      <BroadcastBanner />
      <main className="max-w-6xl mx-auto px-4 py-6">
        <ErrorBoundary fallback={
          <div className="min-h-[40vh] flex items-center justify-center p-8">
            <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow-sm p-8 max-w-md w-full text-center">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-2">
                This page encountered an error.
              </h2>
              <p className="text-sm text-gray-400 dark:text-gray-500 mb-6">
                Try navigating to a different page or reloading.
              </p>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm rounded-lg transition-colors"
              >
                Reload page
              </button>
            </div>
          </div>
        }>
          <Outlet />
        </ErrorBoundary>
      </main>

      {mobileMenuOpen && (
        <div className="fixed inset-0 z-50 md:hidden">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/40"
            onClick={() => setMobileMenuOpen(false)}
          />
          {/* Drawer */}
          <div className="absolute left-0 top-0 bottom-0 w-72 bg-white dark:bg-gray-900 shadow-xl overflow-y-auto">
            <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
              <span className="font-bold text-brand text-lg">SIN</span>
              <button onClick={() => setMobileMenuOpen(false)} aria-label="Close menu">
                <X className="w-5 h-5 text-gray-500 dark:text-gray-400" />
              </button>
            </div>
            <div className="p-4" onClick={() => setMobileMenuOpen(false)}>
              <Sidebar />
            </div>
          </div>
        </div>
      )}

      <KeyboardShortcutsModal />
      <InstallPrompt />
      <BackToTop />
      {/* Floating keyboard shortcuts trigger — always visible in bottom-left corner */}
      <button
        onClick={() => window.dispatchEvent(new CustomEvent("show-shortcuts-help"))}
        aria-label="Keyboard shortcuts"
        title="Keyboard shortcuts (?)"
        className="fixed bottom-6 left-6 z-50 w-8 h-8 rounded-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 shadow-md flex items-center justify-center text-gray-500 dark:text-gray-400 hover:text-brand hover:border-brand dark:hover:border-brand transition-colors text-sm font-medium select-none"
      >
        ?
      </button>
    </div>
  );
}
