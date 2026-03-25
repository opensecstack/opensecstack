import { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import OrganisationList from './pages/OrganisationList'
import AssessmentList from './pages/AssessmentList'
import AssessmentDetail from './pages/AssessmentDetail'
import AuditLog from './pages/AuditLog'
import './App.css'

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
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
        <NavLink
          to="/audit"
          className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
        >
          Audit Log
        </NavLink>
        <button className="nav-item nav-logout" onClick={onLogout}>
          Sign out
        </button>
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Navigate to="/organisations" replace />} />
          <Route path="/organisations" element={<OrganisationList />} />
          <Route path="/organisations/:orgId/assessments" element={<AssessmentList />} />
          <Route path="/assessments/:id" element={<AssessmentDetail />} />
          <Route path="/audit" element={<AuditLog />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState<string | null>(() =>
    localStorage.getItem('nis2compass_token'),
  )

  function handleLogin(t: string) {
    setToken(t)
  }

  function handleLogout() {
    localStorage.removeItem('nis2compass_token')
    setToken(null)
  }

  return (
    <BrowserRouter>
      {token ? (
        <AuthenticatedApp onLogout={handleLogout} />
      ) : (
        <Login onLogin={handleLogin} />
      )}
    </BrowserRouter>
  )
}
