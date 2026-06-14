import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth, type AuthUser } from "@/state/auth";

interface RequireAuthProps {
  children: ReactNode;
  roles?: AuthUser["role"][];
}

export function RequireAuth({ children, roles }: RequireAuthProps): JSX.Element {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  if (roles && !roles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}
