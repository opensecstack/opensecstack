import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Findings from './pages/Findings'
import AuditLog from './pages/AuditLog'
import Login from './pages/Login'
import Landing from './pages/Landing'
import AuthCallback from './pages/AuthCallback'
import './App.css'

function AuthenticatedApp({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="app">
      <nav className="sidebar">
        <div className="logo">
          <span className="logo-icon">🛡</span>
          <span className="logo-text">APIGuard</span>
        </div>
        <NavLink to="/" end className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          Dashboard
        </NavLink>
        <NavLink to="/scans" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          Scans
        </NavLink>
        <NavLink to="/findings" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          Findings
        </NavLink>
        <NavLink to="/audit" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
          Audit Log
        </NavLink>
        <button className="nav-item nav-logout" onClick={onLogout}>
          Sign out
        </button>
      </nav>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('apiguard_token'))

  useEffect(() => {
    const handle = () => setToken(null)
    window.addEventListener('apiguard:logout', handle)
    return () => window.removeEventListener('apiguard:logout', handle)
  }, [])

  function handleLogin(t: string) {
    setToken(t)
  }

  function handleLogout() {
    localStorage.removeItem('apiguard_token')
    setToken(null)
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/auth/callback" element={<AuthCallback />} />
        {!token && <Route path="/login" element={<Login onLogin={handleLogin} />} />}
        <Route path="*" element={
          token
            ? <AuthenticatedApp onLogout={handleLogout} />
            : <Landing onLogin={handleLogin} />
        } />
      </Routes>
    </BrowserRouter>
  )
}
