import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Spinner } from "@/components/Spinner";
import { RequireAuth } from "@/components/auth/RequireAuth";
import { useAuth } from "@/state/auth";

const Landing = lazy(() => import("@/routes/Landing"));
const Home = lazy(() => import("@/routes/Home"));
const Login = lazy(() => import("@/routes/Login"));
const AuthCallback = lazy(() => import("@/routes/AuthCallback"));
const TrackList = lazy(() => import("@/routes/TrackList"));
const TrackDetail = lazy(() => import("@/routes/TrackDetail"));
const LessonViewer = lazy(() => import("@/routes/LessonViewer"));
const LabRunner = lazy(() => import("@/routes/LabRunner"));
const QuizRunner = lazy(() => import("@/routes/QuizRunner"));
const Progress = lazy(() => import("@/routes/Progress"));
const Certifications = lazy(() => import("@/routes/Certifications"));
const AdminCohorts = lazy(() => import("@/routes/AdminCohorts"));
const NotFound = lazy(() => import("@/routes/NotFound"));

function Loading(): JSX.Element {
  return (
    <div className="flex justify-center p-10">
      <Spinner />
    </div>
  );
}

function PublicIndex(): JSX.Element {
  const { user } = useAuth();
  if (user) return <Navigate to="/tracks" replace />;
  return <Landing />;
}

export function App(): JSX.Element {
  return (
    <Suspense fallback={<Loading />}>
      <Routes>
        <Route path="auth/callback" element={<AuthCallback />} />
        <Route index element={<PublicIndex />} />
        <Route element={<Layout />}>
          <Route path="home" element={<Home />} />
          <Route path="login" element={<Login />} />
          <Route path="tracks" element={<TrackList />} />
          <Route path="tracks/:id" element={<TrackDetail />} />
          <Route
            path="lessons/:id"
            element={
              <RequireAuth>
                <LessonViewer />
              </RequireAuth>
            }
          />
          <Route
            path="labs/:id"
            element={
              <RequireAuth>
                <LabRunner />
              </RequireAuth>
            }
          />
          <Route
            path="quizzes/:quizId"
            element={
              <RequireAuth>
                <QuizRunner />
              </RequireAuth>
            }
          />
          <Route path="me/tracks" element={<Navigate to="/tracks" replace />} />
          <Route path="me/home" element={<Navigate to="/home" replace />} />
          <Route
            path="me/progress"
            element={
              <RequireAuth>
                <Progress />
              </RequireAuth>
            }
          />
          <Route
            path="me/certifications"
            element={
              <RequireAuth>
                <Certifications />
              </RequireAuth>
            }
          />
          <Route
            path="admin/cohorts"
            element={
              <RequireAuth roles={["admin"]}>
                <AdminCohorts />
              </RequireAuth>
            }
          />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
