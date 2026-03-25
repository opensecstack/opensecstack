import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Scans from './pages/Scans'
import ScanDetail from './pages/ScanDetail'
import Findings from './pages/Findings'
import './App.css'

export default function App() {
  return (
    <BrowserRouter>
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
        </nav>
        <main className="main">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/findings" element={<Findings />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
