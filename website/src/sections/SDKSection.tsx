import ScrollSection from '../components/ScrollSection'

const sdks = [
  { lang: 'Go', color: '#00ADD8', methods: 49, tests: 102, example: 'client := opensecstack.NewAPIGuardClient(url, key)\nscan, _ := client.CreateScan(ctx, specURL)' },
  { lang: 'Python', color: '#3776AB', methods: 47, tests: 67, example: 'client = APIGuardClient(url, api_key)\nscan = client.create_scan(spec_url=url)' },
  { lang: 'Rust', color: '#CE422B', methods: 40, tests: 75, example: 'let client = APIGuardClient::new(url, key);\nlet scan = client.create_scan(spec_url).await?;' },
]

export default function SDKSection() {
  return (
    <ScrollSection id="sdks">
      <h2 className="section-title"><span className="gradient-text">Multi-Language</span> SDKs</h2>
      <p className="section-subtitle">
        Type-safe clients for APIGuard, NIS2 Compass, and CITADEL. Consistent API across Go, Python, and Rust.
      </p>
      <div className="grid-3">
        {sdks.map(s => (
          <div key={s.lang} className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '1rem' }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }} />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 600 }}>{s.lang}</h3>
            </div>
            <div className="stat-grid" style={{ marginBottom: '1rem' }}>
              <div className="stat-item">
                <div className="stat-value" style={{ fontSize: '1.5rem' }}>{s.methods}</div>
                <div className="stat-label">Methods</div>
              </div>
              <div className="stat-item">
                <div className="stat-value" style={{ fontSize: '1.5rem' }}>{s.tests}</div>
                <div className="stat-label">Tests</div>
              </div>
            </div>
            <pre style={{
              background: '#0a0a1a', borderRadius: 8, padding: '1rem', fontSize: '0.75rem',
              fontFamily: 'var(--mono)', color: '#94a3b8', overflow: 'auto', lineHeight: 1.6,
            }}>
              {s.example}
            </pre>
          </div>
        ))}
      </div>
    </ScrollSection>
  )
}
