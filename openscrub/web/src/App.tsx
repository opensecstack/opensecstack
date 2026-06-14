import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Spinner } from "@/components/Spinner";
import { RequireAuth } from "@/components/auth/RequireAuth";

const Landing = lazy(() => import("@/routes/Landing"));
const Login = lazy(() => import("@/routes/Login"));
const AuthCallback = lazy(() => import("@/routes/AuthCallback"));
const RulesList = lazy(() => import("@/routes/RulesList"));
const AddRule = lazy(() => import("@/routes/AddRule"));
const Mitigations = lazy(() => import("@/routes/Mitigations"));
const Metrics = lazy(() => import("@/routes/Metrics"));
const NotFound = lazy(() => import("@/routes/NotFound"));

function Loading(): JSX.Element {
  return (
    <div className="flex justify-center p-10">
      <Spinner />
    </div>
  );
}

export function App(): JSX.Element {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="auth/callback" element={<AuthCallback />} />
        <Route index element={<Landing />} />
        <Route element={<Layout />}>
          <Route path="login" element={<Login />} />
          <Route
            path="rules"
            element={
              <RequireAuth>
                <RulesList />
              </RequireAuth>
            }
          />
          <Route
            path="rules/new"
            element={
              <RequireAuth>
                <AddRule />
              </RequireAuth>
            }
          />
          <Route
            path="mitigations"
            element={
              <RequireAuth>
                <Mitigations />
              </RequireAuth>
            }
          />
          <Route
            path="metrics"
            element={
              <RequireAuth>
                <Metrics />
              </RequireAuth>
            }
          />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
