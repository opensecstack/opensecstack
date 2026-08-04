import ScrollSection from '../components/ScrollSection'

const sdks = [
  { lang: 'Go', color: '#00ADD8', methods: 49, tests: 102, example: 'client := sin.NewAPIGuardClient(url, key)\nscan, _ := client.CreateScan(ctx, specURL)' },
  { lang: 'Python', color: '#3776AB', methods: 47, tests: 67, example: 'client = APIGuardClient(url, api_key)\nscan = client.create_scan(spec_url=url)' },
  { lang: 'Rust', color: '#CE422B', methods: 40, tests: 75, example: 'let client = APIGuardClient::new(url, key);\nlet scan = client.create_scan(spec_url).await?;' },
  { lang: 'TypeScript', color: '#3178C6', methods: 35, tests: 48, example: 'const client = new APIGuardClient(url, key);\nconst scan = await client.createScan(specUrl);' },
]

export default function SDKSection() {
  return (
    <ScrollSection id="sdks">
      <h2 className="section-title"><span className="gradient-text">Multi-Language</span> SDKs</h2>
      <p className="section-subtitle">
        Type-safe APIGuard clients with a consistent API across Go, Python, Rust, and TypeScript.
      </p>
      <div className="grid-3">
        {sdks.map(s => (
          <div key={s.lang} className="glass-card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '1rem' }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: s.color }} />
              <h3 className="card-title">{s.lang}</h3>
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
