const links = [
  { label: 'Platforms', href: '#platforms' },
  { label: 'APIGuard', href: '#apiguard' },
  { label: 'NIS2 Compass', href: '#nis2compass' },
  { label: 'CITADEL', href: '#citadel' },
  { label: 'SDKs', href: '#sdks' },
  { label: 'Roadmap', href: '#roadmap' },
]

export default function Navbar() {
  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 100,
      background: 'rgba(5,5,16,0.85)', backdropFilter: 'blur(12px)',
      borderBottom: '1px solid rgba(0,240,255,0.08)',
      padding: '0 2rem', height: 56, display: 'flex', alignItems: 'center', gap: '2rem',
    }}>
      <a href="#" style={{ fontWeight: 700, fontSize: '1.1rem', color: '#00f0ff', textDecoration: 'none' }}>
        opensecstack
      </a>
      <div style={{ display: 'flex', gap: '1.5rem', marginLeft: 'auto', fontSize: '0.875rem' }}>
        {links.map(l => (
          <a key={l.href} href={l.href} style={{ color: '#94a3b8', textDecoration: 'none' }}>
            {l.label}
          </a>
        ))}
      </div>
      <a
        href="https://github.com/opensecstack/opensecstack"
        target="_blank"
        rel="noopener noreferrer"
        style={{
          padding: '6px 16px', borderRadius: 8, fontSize: '0.8rem', fontWeight: 600,
          background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.25)',
          color: '#00f0ff', textDecoration: 'none',
        }}
      >
        GitHub
      </a>
    </nav>
  )
}
