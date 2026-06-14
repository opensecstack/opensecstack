import { Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Login from "./pages/Login";
import Landing from "./pages/Landing";
import AuthCallback from "./pages/AuthCallback";
import Dashboard from "./pages/Dashboard";
import Scan from "./pages/Scan";
import ThreatFeed from "./pages/ThreatFeed";
import Metrics from "./pages/Metrics";
import VideoScan from "./pages/VideoScan";
import { getToken } from "./lib/auth";

function Protected({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />;
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <main className="flex-1 p-8">{children}</main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/auth/callback" element={<AuthCallback />} />
      <Route path="/login" element={<Login />} />
      <Route path="/" element={getToken() ? <Protected><Dashboard /></Protected> : <Landing />} />
      <Route path="/scan" element={<Protected><Scan /></Protected>} />
      <Route path="/threatfeed" element={<Protected><ThreatFeed /></Protected>} />
      <Route path="/metrics" element={<Protected><Metrics /></Protected>} />
      <Route path="/video" element={<Protected><VideoScan /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
