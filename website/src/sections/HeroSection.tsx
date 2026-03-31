import ScrollSection from '../components/ScrollSection'

export default function HeroSection() {
  return (
    <ScrollSection className="hero" id="hero">
      <div style={{ paddingTop: '15vh', maxWidth: 720 }}>
        <h1 style={{ fontSize: 'clamp(2.5rem, 6vw, 4.5rem)', fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1.1 }}>
          <span className="gradient-text">Open-Source</span> Security<br />
          &amp; Compliance Platform
        </h1>
        <p style={{ marginTop: '1.5rem', fontSize: '1.2rem', color: '#94a3b8', lineHeight: 1.7, maxWidth: 560 }}>
          8 platforms. 3 SDKs. 1 immutable governance chain.
          Built for the EU Digital Decade.
        </p>
        <div className="stat-grid" style={{ marginTop: '3rem' }}>
          <div className="stat-item">
            <div className="stat-value">10/10</div>
            <div className="stat-label">OWASP API Top 10</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">10</div>
            <div className="stat-label">NIS2 Controls</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">5</div>
            <div className="stat-label">MARSHAL Gates</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">3</div>
            <div className="stat-label">SDKs (Go/Py/Rust)</div>
          </div>
        </div>
        <div style={{ marginTop: '2.5rem', display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <a href="#platforms" style={{
            padding: '12px 28px', borderRadius: 10, fontWeight: 600, fontSize: '0.95rem',
            background: 'linear-gradient(135deg, #00f0ff, #7c3aed)', color: '#050510',
            textDecoration: 'none',
          }}>
            Explore Platforms
          </a>
          <a href="https://github.com/opensecstack/opensecstack" target="_blank" rel="noopener noreferrer" style={{
            padding: '12px 28px', borderRadius: 10, fontWeight: 600, fontSize: '0.95rem',
            border: '1px solid rgba(0,240,255,0.3)', color: '#00f0ff',
            textDecoration: 'none',
          }}>
            View on GitHub
          </a>
        </div>
      </div>
    </ScrollSection>
  )
}
