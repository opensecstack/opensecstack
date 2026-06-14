import { Link, NavLink, Outlet } from "react-router-dom";
import { useTranslation } from "react-i18next";
import clsx from "clsx";
import { Globe, LogOut, User } from "lucide-react";
import { useLocale } from "@/state/locale";
import { useAuth } from "@/state/auth";
import { Button } from "./Button";

export function Layout(): JSX.Element {
  const { t } = useTranslation("common");
  const { locale, setLocale } = useLocale();
  const { user, logout } = useAuth();

  const navItems = [
    { to: "/", key: "home" as const },
    { to: "/tracks", key: "tracks" as const },
    { to: "/me/progress", key: "progress" as const },
    { to: "/me/certifications", key: "certifications" as const },
  ];

  return (
    <div className="flex min-h-full flex-col">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3">
          <Link to="/" className="text-lg font-bold text-brand">
            {t("appTitle")}
          </Link>
          <nav className="hidden gap-2 md:flex">
            {navItems.map(({ to, key }) => (
              <NavLink
                key={key}
                to={to}
                end={to === "/"}
                className={({ isActive }) =>
                  clsx(
                    "rounded-md px-3 py-1.5 text-sm font-medium transition",
                    isActive ? "bg-slate-100 text-slate-900" : "text-slate-600 hover:bg-slate-50",
                  )
                }
              >
                {t(`nav.${key}`)}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1 text-xs text-slate-600">
              <Globe className="h-4 w-4" aria-hidden="true" />
              <span className="sr-only">{t("localeSwitch.label")}</span>
              <select
                aria-label={t("localeSwitch.label")}
                value={locale}
                onChange={(e) => setLocale(e.target.value === "en" ? "en" : "sq")}
                className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs"
              >
                <option value="sq">{t("localeSwitch.sq")}</option>
                <option value="en">{t("localeSwitch.en")}</option>
              </select>
            </label>
            {user ? (
              <div className="flex items-center gap-2">
                <span
                  className="hidden items-center gap-1 text-sm text-slate-700 sm:flex"
                  aria-label={t("user.menuLabel")}
                >
                  <User className="h-4 w-4" aria-hidden="true" />
                  {user.display_name}
                </span>
                <Button variant="ghost" onClick={logout} aria-label={t("nav.logout")}>
                  <LogOut className="h-4 w-4" aria-hidden="true" />
                  <span className="hidden sm:inline">{t("nav.logout")}</span>
                </Button>
              </div>
            ) : (
              <Link
                to="/login"
                className="rounded-md bg-brand px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
              >
                {t("nav.login")}
              </Link>
            )}
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 bg-white">
        <div className="mx-auto max-w-6xl px-4 py-3 text-center text-xs text-slate-500">
          {t("footer.copyright")}
        </div>
      </footer>
    </div>
  );
}
