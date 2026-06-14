import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "@/state/auth";

export function RequireAuth() {
  const token = useAuthStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return <Outlet />;
}
