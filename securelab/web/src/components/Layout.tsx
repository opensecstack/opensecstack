import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { ShieldCheck, LogOut, LayoutDashboard, FlaskConical, ClipboardList, Map, SearchX } from "lucide-react";
import clsx from "clsx";
import { useAuthStore } from "@/store/authStore";

export function Layout(): JSX.Element {
  const navigate = useNavigate();
  const token = useAuthStore((s) => s.token);
  const sub = useAuthStore((s) => s.sub);
  const clearToken = useAuthStore((s) => s.clearToken);

  const handleLogout = (): void => {
    clearToken();
    navigate("/login");
  };

  const navItem = ({ isActive }: { isActive: boolean }): string =>
    clsx(
      "flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition",
      isActive
        ? "bg-slate-900 text-white"
        : "text-slate-600 hover:bg-slate-200 hover:text-slate-900",
    );

  return (
    <div className="min-h-screen flex">
      {/* Sidebar */}
      <aside className="w-56 bg-white border-r border-slate-200 flex flex-col">
        <div className="flex items-center gap-2 px-4 py-4 border-b border-slate-200">
          <ShieldCheck className="h-5 w-5 text-slate-900" />
          <span className="font-semibold text-slate-900">SecureLab</span>
        </div>
        {token && (
          <nav className="flex-1 p-3 space-y-1">
            <NavLink to="/dashboard" className={navItem}>
              <LayoutDashboard className="h-4 w-4" />
              Dashboard
            </NavLink>
            <NavLink to="/scenarios" className={navItem}>
              <FlaskConical className="h-4 w-4" />
              Scenarios
            </NavLink>
            <NavLink to="/results" className={navItem}>
              <ClipboardList className="h-4 w-4" />
              Results
            </NavLink>
            <NavLink to="/mitre" className={navItem}>
              <Map className="h-4 w-4" />
              MITRE Map
            </NavLink>
            <NavLink to="/gaps" className={navItem}>
              <SearchX className="h-4 w-4" />
              Gap Analysis
            </NavLink>
          </nav>
        )}
        {token && (
          <div className="p-3 border-t border-slate-200">
            {sub && <p className="text-xs text-slate-500 mb-2 truncate">{sub}</p>}
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 w-full px-3 py-2 rounded-md text-sm text-slate-600 hover:bg-slate-100 hover:text-slate-900 transition"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </button>
          </div>
        )}
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0">
        <header className="bg-white border-b border-slate-200 px-6 py-3 flex items-center justify-between">
          <h1 className="text-sm font-medium text-slate-700">SecureLab — Attack Simulation & Detection Validation</h1>
          {sub && (
            <span className="text-xs text-slate-500">{sub}</span>
          )}
        </header>
        <main className="flex-1 p-6 overflow-auto">
          <Outlet />
        </main>
        <footer className="border-t border-slate-200 py-3 px-6 text-xs text-slate-500">
          SecureLab v1.0.0 — OpenSecStack
        </footer>
      </div>
    </div>
  );
}
