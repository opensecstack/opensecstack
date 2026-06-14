import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Spinner } from "@/components/Spinner";
import { RequireAuth } from "@/components/auth/RequireAuth";

const Landing = lazy(() => import("@/pages/Landing"));
const Login = lazy(() => import("@/pages/Login"));
const AuthCallback = lazy(() => import("@/pages/AuthCallback"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Scenarios = lazy(() => import("@/pages/Scenarios"));
const RunScenario = lazy(() => import("@/pages/RunScenario"));
const Results = lazy(() => import("@/pages/Results"));
const ResultDetail = lazy(() => import("@/pages/ResultDetail"));
const MitreMap = lazy(() => import("@/pages/MitreMap"));
const GapAnalysis = lazy(() => import("@/pages/GapAnalysis"));

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
            path="dashboard"
            element={
              <RequireAuth>
                <Dashboard />
              </RequireAuth>
            }
          />
          <Route
            path="scenarios"
            element={
              <RequireAuth>
                <Scenarios />
              </RequireAuth>
            }
          />
          <Route
            path="scenarios/:id/run"
            element={
              <RequireAuth>
                <RunScenario />
              </RequireAuth>
            }
          />
          <Route
            path="results"
            element={
              <RequireAuth>
                <Results />
              </RequireAuth>
            }
          />
          <Route
            path="results/:id"
            element={
              <RequireAuth>
                <ResultDetail />
              </RequireAuth>
            }
          />
          <Route
            path="mitre"
            element={
              <RequireAuth>
                <MitreMap />
              </RequireAuth>
            }
          />
          <Route
            path="gaps"
            element={
              <RequireAuth>
                <GapAnalysis />
              </RequireAuth>
            }
          />
        </Route>
      </Routes>
    </Suspense>
  );
}
