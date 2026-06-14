import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Playbook automation', 'Evidence chain (hash-linked)', 'SLA tracking',
  'Stakeholder notifications', 'Post-mortem reports', 'CSIRT coordination',
]

export default function IRFlowSection() {
  return (
    <ScrollSection id="irflow">
      <h2 className="section-title"><span className="gradient-text">IRFlow</span></h2>
      <p className="section-subtitle">
        Structured incident response platform. Full lifecycle from detection to post-mortem with automated playbooks and evidence chain.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#f59e0b' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Incident Lifecycle</h3>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '0.85rem', color: '#94a3b8' }}>
              {['Detection', 'Triage', 'Containment', 'Eradication', 'Recovery', 'Post-mortem'].map((s, i, arr) => (
                <span key={s}>
                  <span style={{ color: '#f59e0b' }}>{s}</span>
                  {i < arr.length - 1 && <span style={{ color: '#334155', margin: '0 6px' }}>&rarr;</span>}
                </span>
              ))}
            </div>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Evidence Chain</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Every incident artefact is hash-linked into an immutable evidence chain.
              CITADEL WORM log provides tamper-proof custody trail for regulatory proof.
            </p>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>NIS2 Reporting</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Automated 24-hour early warning and 72-hour incident notification
              aligned with NIS2 Directive Article 23 reporting obligations.
            </p>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
