import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "@/state/auth";

interface Props {
  children: ReactNode;
}

export function RequireAuth({ children }: Props): JSX.Element {
  const token = useAuth((s) => s.token);
  const location = useLocation();
  if (!token) {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return <>{children}</>;
}
