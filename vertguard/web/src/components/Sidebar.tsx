import { NavLink, useNavigate } from "react-router-dom";
import { Shield, Search, Activity, BarChart3, LogOut, Video } from "lucide-react";
import { useTranslation } from "react-i18next";
import { clearToken } from "../lib/auth";

export default function Sidebar() {
  const { t } = useTranslation();
  const nav = useNavigate();
  const links = [
    { to: "/", label: t("common:nav.dashboard"), icon: Shield },
    { to: "/scan", label: t("common:nav.scan"), icon: Search },
    { to: "/threatfeed", label: t("common:nav.threatfeed"), icon: Activity },
    { to: "/metrics", label: t("common:nav.metrics"), icon: BarChart3 },
    { to: "/video", label: t("common:nav.video"), icon: Video },
  ];
  return (
    <aside className="w-56 bg-slate-900 border-r border-slate-800 p-4 flex flex-col">
      <div className="text-lg font-semibold mb-6 text-indigo-400">{t("common:app_name")}</div>
      <nav className="flex flex-col gap-1 flex-1">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === "/"}
            className={({ isActive }) =>
              `flex items-center gap-2 px-3 py-2 rounded text-sm ${
                isActive ? "bg-indigo-500/20 text-indigo-300" : "hover:bg-slate-800 text-slate-300"
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>
      <button
        onClick={() => {
          clearToken();
          nav("/login");
        }}
        className="flex items-center gap-2 px-3 py-2 text-sm text-slate-400 hover:text-slate-100"
      >
        <LogOut size={16} /> {t("common:nav.logout")}
      </button>
    </aside>
  );
}
