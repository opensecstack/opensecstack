import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Posts, comments & threaded discussions', 'Tag-based taxonomy & series',
  'Full-text search (Meilisearch)', 'Spaces (topic communities)',
  'Notifications & activity feed', 'TOTP 2FA & API keys',
]

export default function SINSection() {
  return (
    <ScrollSection id="sin">
      <h2 className="section-title"><span className="gradient-text">SIN Community</span></h2>
      <p className="section-subtitle">
        Developer knowledge hub for the opensecstack ecosystem. A self-hosted community platform
        where practitioners share research, ask questions, and build the open-source security commons.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#22c55e' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Architecture</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">API</span> Go HTTP server — chi · zap · pgx</div>
            <div><span className="tech-tag">UI</span> React + TypeScript SPA</div>
            <div><span className="tech-tag">Search</span> Meilisearch full-text index</div>
            <div><span className="tech-tag">Auth</span> sinauth — OAuth2 / OIDC + TOTP 2FA</div>
            <div><span className="tech-tag">Store</span> PostgreSQL 16 with JSONB</div>
            <div><span className="tech-tag">Licence</span> Apache 2.0 — self-host freely</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
