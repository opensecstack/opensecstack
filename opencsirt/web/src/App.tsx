import { lazy, Suspense } from "react";
import { Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Spinner } from "@/components/Spinner";
import { RequireAuth } from "@/components/auth/RequireAuth";

const Landing = lazy(() => import("@/routes/Landing"));
const Login = lazy(() => import("@/routes/Login"));
const AuthCallback = lazy(() => import("@/routes/AuthCallback"));
const Constituencies = lazy(() => import("@/routes/Constituencies"));
const Incidents = lazy(() => import("@/routes/Incidents"));
const IncidentDetail = lazy(() => import("@/routes/IncidentDetail"));
const Advisories = lazy(() => import("@/routes/Advisories"));
const AdvisoryDetail = lazy(() => import("@/routes/AdvisoryDetail"));
const Peers = lazy(() => import("@/routes/Peers")); // Phase 3.1 placeholder
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
          <Route path="constituencies" element={<RequireAuth><Constituencies /></RequireAuth>} />
          <Route path="incidents" element={<RequireAuth><Incidents /></RequireAuth>} />
          <Route path="incidents/:id" element={<RequireAuth><IncidentDetail /></RequireAuth>} />
          <Route path="advisories" element={<RequireAuth><Advisories /></RequireAuth>} />
          <Route path="advisories/:id" element={<RequireAuth><AdvisoryDetail /></RequireAuth>} />
          <Route path="peers" element={<RequireAuth><Peers /></RequireAuth>} />
          <Route path="metrics" element={<RequireAuth><Metrics /></RequireAuth>} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
