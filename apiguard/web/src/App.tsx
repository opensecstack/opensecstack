import { useState } from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Findings from './pages/Findings'
import AuditLog from './pages/AuditLog'
import Login from './pages/Login'
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
        </Routes>
      </main>
    </div>
  )
}

export default function App() {
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('apiguard_token'))

  function handleLogin(t: string) {
    setToken(t)
  }

  function handleLogout() {
    localStorage.removeItem('apiguard_token')
    setToken(null)
  }

  return (
    <BrowserRouter>
      {token
        ? <AuthenticatedApp onLogout={handleLogout} />
        : <Login onLogin={handleLogin} />
      }
    </BrowserRouter>
  )
}
