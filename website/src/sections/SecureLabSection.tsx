import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Malware analysis sandbox', 'Network traffic capture', 'Automated detonation',
  'IOC extraction', 'Snapshot & rollback', 'API for automation',
]

export default function SecureLabSection() {
  return (
    <ScrollSection id="securelab">
      <h2 className="section-title"><span className="gradient-text">SecureLab</span></h2>
      <p className="section-subtitle">
        Isolated sandbox environments for malware analysis, vulnerability research, and security testing.
        Containerised with CITADEL-governed lifecycle.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#06b6d4' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Architecture</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">Spawn</span> On-demand container creation</div>
            <div><span className="tech-tag">Isolate</span> Network namespace + CITADEL sandbox</div>
            <div><span className="tech-tag">Detonate</span> Automated malware execution</div>
            <div><span className="tech-tag">Capture</span> Full packet + syscall tracing</div>
            <div><span className="tech-tag">Extract</span> IOC export to ThreatFlow</div>
            <div><span className="tech-tag">Destroy</span> Secure cleanup with WORM proof</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
