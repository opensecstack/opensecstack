import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Multi-CSIRT coordination', 'NIS2 incident reporting (24h/72h)', 'Cross-border sharing',
  'Vulnerability disclosure', 'Situational awareness', 'EU-wide dashboard',
]

export default function OpenCSIRTSection() {
  return (
    <ScrollSection id="opencsirt">
      <h2 className="section-title"><span className="gradient-text">OpenCSIRT</span></h2>
      <p className="section-subtitle">
        Computer Security Incident Response Team operations platform for EU member states.
        Cross-border incident coordination aligned with NIS2 Directive reporting requirements.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#8b5cf6' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>NIS2 Reporting</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Automated 24-hour early warning and 72-hour incident notification
              for national competent authorities. Template-driven reporting aligned
              with ENISA incident taxonomy.
            </p>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Cross-Border Coordination</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Shared IOC feeds via ThreatFlow TAXII. Multi-CSIRT incident
              handoff with hash-linked evidence chain. EU-CyCLONe integration
              for large-scale crisis management.
            </p>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Vulnerability Disclosure</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Coordinated vulnerability disclosure (CVD) platform. Researcher
              submission portal, triage workflow, and public advisory publishing
              with CVSS scoring from APIGuard.
            </p>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
