import { Link } from 'react-router-dom'

const links = [
  { label: 'Platforms', href: '#platforms' },
  { label: 'APIGuard', href: '#apiguard' },
  { label: 'NIS2', href: '#nis2compass' },
  { label: 'CITADEL', href: '#citadel' },
  { label: 'SDKs', href: '#sdks' },
  { label: 'Roadmap', href: '#roadmap' },
]

export default function Navbar() {
  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      background: 'rgba(3,3,8,0.7)',
      backdropFilter: 'blur(20px) saturate(150%)',
      borderBottom: '1px solid rgba(0,240,255,0.06)',
      padding: '0 2rem', height: 56,
      display: 'flex', alignItems: 'center', gap: '2rem',
    }}>
      <a href="#" style={{
        fontWeight: 800, fontSize: '1.1rem', letterSpacing: '0.04em',
        background: 'linear-gradient(135deg, #00f0ff, #7c3aed)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        textDecoration: 'none',
      }}>
        SIN
      </a>
      <div style={{ display: 'flex', gap: '1.5rem', marginLeft: 'auto', fontSize: '0.85rem' }}>
        {links.map(l => (
          <a key={l.href} href={l.href} style={{
            color: '#8892a8', textDecoration: 'none',
            transition: 'color 0.2s, text-shadow 0.2s',
          }}>
            {l.label}
          </a>
        ))}
      </div>
      <Link to="/citadelos" style={{
        padding: '7px 14px', borderRadius: 9, fontSize: '0.8rem', fontWeight: 600,
        background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)',
        color: '#ef4444', textDecoration: 'none', transition: 'all 0.2s',
      }}>
        CitadelOS
      </Link>
      <a
        href="https://github.com/opensecstack/opensecstack"
        target="_blank"
        rel="noopener noreferrer"
        style={{
          padding: '7px 18px', borderRadius: 9, fontSize: '0.8rem', fontWeight: 600,
          background: 'rgba(0,240,255,0.06)',
          border: '1px solid rgba(0,240,255,0.2)',
          color: '#00f0ff', textDecoration: 'none',
          transition: 'all 0.2s',
          boxShadow: '0 0 12px rgba(0,240,255,0.08)',
        }}
      >
        GitHub
      </a>
    </nav>
  )
}
