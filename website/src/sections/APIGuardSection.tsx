import ScrollSection from '../components/ScrollSection'

const modules = [
  'A1 BOLA', 'A2 Broken Auth', 'A3 Mass Assignment', 'A4 Rate Limiting',
  'A5 Function Auth', 'A6 Business Flow', 'A7 SSRF', 'A8 Misconfiguration',
  'A9 Inventory', 'A10 Unsafe Consumption',
]

export default function APIGuardSection() {
  return (
    <ScrollSection id="apiguard">
      <h2 className="section-title"><span className="gradient-text">APIGuard</span></h2>
      <p className="section-subtitle">
        Automated OWASP API Top 10 detection. Rust-powered parsing. Go orchestration. Zero false positives by design.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>OWASP API Top 10 Coverage</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {modules.map(m => (
              <div key={m} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#10b981' }}>&#10003;</span> {m}
              </div>
            ))}
          </div>
        </div>
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Architecture</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">L1</span> Rust Parser (OpenAPI 3.x, Swagger 2.0)</div>
            <div><span className="tech-tag">L2</span> Test Generation Engine</div>
            <div><span className="tech-tag">L3</span> Rust Analysis Modules (OWASP)</div>
            <div><span className="tech-tag">L4</span> CVSS 3.1 Scoring</div>
            <div><span className="tech-tag">L5</span> Go HTTP Orchestration</div>
            <div><span className="tech-tag">L6</span> PostgreSQL + Redis</div>
            <div><span className="tech-tag">L7</span> Report Formats (PDF/JSON/SARIF)</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
