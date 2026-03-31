import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'PII detection (NER + regex)', 'Log sanitisation', 'Database redaction',
  'File export filtering', 'GDPR erasure proof', 'Audit trail',
]

export default function OpenScrubSection() {
  return (
    <ScrollSection id="openscrub">
      <h2 className="section-title"><span className="gradient-text">OpenScrub</span></h2>
      <p className="section-subtitle">
        Data sanitisation engine. Automated PII detection and redaction for logs, databases, and exports.
        GDPR Article 17 right-to-erasure enforcement at infrastructure level.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#10b981' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Architecture</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">Detect</span> NER + regex PII pattern matching</div>
            <div><span className="tech-tag">Classify</span> Sensitivity scoring (GDPR categories)</div>
            <div><span className="tech-tag">Redact</span> Configurable sanitisation strategies</div>
            <div><span className="tech-tag">Verify</span> Post-redaction validation</div>
            <div><span className="tech-tag">Prove</span> Erasure certification for DPA</div>
            <div><span className="tech-tag">Audit</span> CITADEL WORM chain for all actions</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
