import { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { ErrorBoundary } from './components/ErrorBoundary'
import Login from './pages/Login'
import OrganisationList from './pages/OrganisationList'
import OrganisationDetail from './pages/OrganisationDetail'
import AssessmentList from './pages/AssessmentList'
import AssessmentDetail from './pages/AssessmentDetail'
import GapAnalysis from './pages/GapAnalysis'
import AuditLog from './pages/AuditLog'
import APIKeyManagement from './pages/APIKeyManagement'
import type { Role } from './types'
import { decodeTokenRole, saveAuth, loadAuth, hasRole } from './auth'
import './App.css'

const ROLE_BADGE_STYLES: Record<Role, { bg: string; color: string }> = {
  viewer:   { bg: '#64748b22', color: '#94a3b8' },
  auditor:  { bg: '#3b82f622', color: '#60a5fa' },
  assessor: { bg: '#6366f122', color: '#818cf8' },
  admin:    { bg: '#ef444422', color: '#f87171' },
}

function AuthenticatedApp({ role, onLogout }: { role: Role; onLogout: () => void }) {
  const badge = ROLE_BADGE_STYLES[role]
  return (
    <div className="app">
      <nav className="sidebar">
        <div className="logo">
          <span className="logo-icon">&#x2316;</span>
          <span className="logo-text">NIS2 Compass</span>
        </div>
        <NavLink
          to="/organisations"
          className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
        >
          Organisations
        </NavLink>
        {hasRole(role, 'admin') && (
          <NavLink
            to="/api-keys"
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
          >
            API Keys
          </NavLink>
        )}
        {hasRole(role, 'auditor') && (
          <NavLink
            to="/audit"
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
          >
            Audit Log
          </NavLink>
        )}
        <div style={{ marginTop: 'auto', padding: '12px 0' }}>
          <span
            style={{
              display: 'inline-block',
              background: badge.bg,
              color: badge.color,
              border: `1px solid ${badge.color}44`,
              borderRadius: 4,
              padding: '2px 8px',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              marginBottom: 8,
            }}
          >
            {role}
          </span>
          <button className="nav-item nav-logout" onClick={onLogout}>
            Sign out
          </button>
        </div>
      </nav>
      <main className="main">
        <ErrorBoundary>
          <Routes>
            <Route path="/" element={<Navigate to="/organisations" replace />} />
            <Route path="/organisations" element={<OrganisationList role={role} />} />
            <Route path="/organisations/:id" element={<OrganisationDetail role={role} />} />
            <Route path="/organisations/:orgId/assessments" element={<AssessmentList />} />
            <Route path="/assessments/:id" element={<AssessmentDetail role={role} />} />
            <Route path="/assessments/:id/gaps" element={<GapAnalysis role={role} />} />
            <Route path="/api-keys" element={<APIKeyManagement role={role} />} />
            <Route path="/audit" element={<AuditLog role={role} />} />
          </Routes>
        </ErrorBoundary>
      </main>
    </div>
  )
}

export default function App() {
  const [auth, setAuth] = useState<{ token: string; role: Role } | null>(() => loadAuth())

  function handleLogin(token: string) {
    const role = decodeTokenRole(token) ?? 'viewer'
    saveAuth(token, role)
    setAuth({ token, role })
  }

  function handleLogout() {
    localStorage.removeItem('nis2compass_token')
    localStorage.removeItem('nis2compass_role')
    setAuth(null)
  }

  return (
    <BrowserRouter>
      {auth ? (
        <AuthenticatedApp role={auth.role} onLogout={handleLogout} />
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </BrowserRouter>
  )
}
