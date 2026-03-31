import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Interactive labs', 'Skill assessments', 'Certification tracking',
  'ENISA framework alignment', 'Team progress dashboard', 'Custom curricula',
]

export default function CyberPathSection() {
  return (
    <ScrollSection id="cyberpath">
      <h2 className="section-title"><span className="gradient-text">CyberPath</span></h2>
      <p className="section-subtitle">
        Hands-on cybersecurity training platform with interactive labs, skill assessments,
        and certification tracking. Aligned with ENISA cybersecurity skills framework.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#e040fb' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Training Tracks</h3>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
              <div><span className="tech-tag">Track 1</span> API Security (APIGuard hands-on)</div>
              <div><span className="tech-tag">Track 2</span> NIS2 Compliance (NIS2 Compass)</div>
              <div><span className="tech-tag">Track 3</span> Incident Response (IRFlow)</div>
              <div><span className="tech-tag">Track 4</span> Threat Intelligence (ThreatFlow)</div>
              <div><span className="tech-tag">Track 5</span> Governance &amp; Audit (CITADEL)</div>
            </div>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>SecureLab Integration</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Live sandbox environments powered by SecureLab. Each lab runs
              in a CITADEL-governed container with isolated networking and auto-cleanup.
            </p>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
