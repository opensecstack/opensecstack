import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Users, Shield, Settings, LogOut, Key, Globe, FileText, Activity, MonitorDot } from 'lucide-react'

const nav = [
  { to: '/admin/users',     label: 'Users',              icon: Users },
  { to: '/admin/clients',   label: 'Applications',       icon: Key },
  { to: '/admin/groups',    label: 'Groups',             icon: Shield },
  { to: '/admin/providers', label: 'Identity Providers', icon: Globe },
  { to: '/admin/policies',  label: 'Policies',           icon: FileText },
  { to: '/admin/sessions',  label: 'Sessions',           icon: MonitorDot },
  { to: '/admin/audit',     label: 'Audit Log',          icon: Activity },
  { to: '/admin/settings',  label: 'Settings',           icon: Settings },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const navigate = useNavigate()

  const logout = () => {
    localStorage.removeItem('sinauth_token')
    navigate('/login')
  }

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#f3f4f6' }}>
      <aside style={{ width: 256, background: '#1a2d7a', color: 'white', display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '24px', borderBottom: '1px solid #2541b2' }}>
          <div style={{ fontSize: 20, fontWeight: 700 }}>sin<span style={{ color: '#a5b4fc' }}>auth</span></div>
          <div style={{ fontSize: 11, color: '#a5b4fc', marginTop: 4 }}>Identity Provider</div>
        </div>
        <nav style={{ flex: 1, padding: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {nav.map(({ to, label, icon: Icon }) => {
            const active = location.pathname.startsWith(to)
            return (
              <Link
                key={to}
                to={to}
                style={{
                  display: 'flex', alignItems: 'center', gap: 12,
                  padding: '8px 12px', borderRadius: 8, fontSize: 14,
                  textDecoration: 'none',
                  background: active ? '#2f4bc7' : 'transparent',
                  color: active ? 'white' : '#c7d2fe',
                }}
              >
                <Icon size={16} />
                {label}
              </Link>
            )
          })}
        </nav>
        <div style={{ padding: 16, borderTop: '1px solid #2541b2' }}>
          <button
            onClick={logout}
            style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '8px 12px', borderRadius: 8, fontSize: 14,
              background: 'transparent', border: 'none', color: '#c7d2fe',
              cursor: 'pointer', width: '100%',
            }}
          >
            <LogOut size={16} />
            Logout
          </button>
        </div>
      </aside>
      <main style={{ flex: 1, overflow: 'auto', padding: 32 }}>
        {children}
      </main>
    </div>
  )
}
