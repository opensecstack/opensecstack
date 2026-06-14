import { Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Consent from './pages/Consent'
import ResetPassword from './pages/ResetPassword'
import VerifyEmail from './pages/VerifyEmail'
import SocialCallback from './pages/SocialCallback'
import OAuthLogin from './pages/OAuthLogin'
import Users from './pages/admin/Users'
import Clients from './pages/admin/Clients'
import Groups from './pages/admin/Groups'
import Providers from './pages/admin/Providers'
import Policies from './pages/admin/Policies'
import Settings from './pages/admin/Settings'
import Sessions from './pages/admin/Sessions'
import AuditLog from './pages/admin/AuditLog'
import Register from './pages/Register'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('sinauth_token') ?? sessionStorage.getItem('sinauth_token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route path="/oauth/login" element={<OAuthLogin />} />
      <Route path="/reset-password" element={<ResetPassword />} />
      <Route path="/verify-email" element={<VerifyEmail />} />
      <Route path="/" element={<SocialCallback />} />
      <Route path="/oauth/consent" element={<Consent />} />
      <Route path="/admin" element={<Navigate to="/admin/users" replace />} />
      <Route path="/admin/users"     element={<RequireAuth><Users /></RequireAuth>} />
      <Route path="/admin/clients"   element={<RequireAuth><Clients /></RequireAuth>} />
      <Route path="/admin/groups"    element={<RequireAuth><Groups /></RequireAuth>} />
      <Route path="/admin/providers" element={<RequireAuth><Providers /></RequireAuth>} />
      <Route path="/admin/policies"  element={<RequireAuth><Policies /></RequireAuth>} />
      <Route path="/admin/sessions"  element={<RequireAuth><Sessions /></RequireAuth>} />
      <Route path="/admin/audit"     element={<RequireAuth><AuditLog /></RequireAuth>} />
      <Route path="/admin/settings"  element={<RequireAuth><Settings /></RequireAuth>} />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  )
}
