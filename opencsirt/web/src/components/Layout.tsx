import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { ShieldAlert, LogOut } from "lucide-react";
import clsx from "clsx";
import { useAuth } from "@/state/auth";
import { useLocale } from "@/state/locale";
import { HealthBadge } from "@/components/HealthBadge";

export function Layout(): JSX.Element {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const token = useAuth((s) => s.token);
  const logout = useAuth((s) => s.logout);
  const locale = useLocale((s) => s.locale);
  const setLocale = useLocale((s) => s.setLocale);

  const handleLogout = (): void => {
    logout();
    navigate("/login");
  };

  const navItem = ({ isActive }: { isActive: boolean }): string =>
    clsx(
      "px-3 py-1.5 rounded-md text-sm",
      isActive ? "bg-slate-900 text-white" : "text-slate-700 hover:bg-slate-200",
    );

  return (
    <div className="min-h-screen flex flex-col">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center gap-4">
          <div className="flex items-center gap-2 font-semibold">
            <ShieldAlert className="h-5 w-5" />
            {t("app_name")}
          </div>
          {token && (
            <nav className="flex items-center gap-1">
              <NavLink to="/incidents" className={navItem}>{t("nav.incidents")}</NavLink>
              <NavLink to="/advisories" className={navItem}>{t("nav.advisories")}</NavLink>
              <NavLink to="/constituencies" className={navItem}>{t("nav.constituencies")}</NavLink>
              <NavLink to="/peers" className={navItem}>{t("nav.peers")}</NavLink>
              <NavLink to="/metrics" className={navItem}>{t("nav.metrics")}</NavLink>
            </nav>
          )}
          <div className="ml-auto flex items-center gap-3">
            <HealthBadge />
            <select
              value={locale}
              onChange={(e) => setLocale(e.target.value as "sq" | "en")}
              className="text-sm border border-slate-300 rounded-md px-2 py-1"
              aria-label="locale"
            >
              <option value="sq">SQ</option>
              <option value="en">EN</option>
            </select>
            {token && (
              <button onClick={handleLogout} className="inline-flex items-center gap-1 text-sm text-slate-600 hover:text-slate-900">
                <LogOut className="h-4 w-4" />
                {t("nav.logout")}
              </button>
            )}
          </div>
        </div>
      </header>
      <main className="flex-1 max-w-6xl mx-auto w-full px-4 py-6">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 py-3 text-center text-xs text-slate-500">
        {t("footer", { version: "1.0.0" })}
      </footer>
    </div>
  );
}
