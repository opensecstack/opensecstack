import ScrollSection from '../components/ScrollSection'
import { marshalGates } from '../data/marshalGates'

export default function CitadelSection() {
  return (
    <ScrollSection id="citadel">
      <h2 className="section-title"><span className="gradient-text">CITADEL</span> Governance</h2>
      <p className="section-subtitle">
        Immutable WORM audit chain, MARSHAL 5-gate evaluation, VIGIL health monitoring, and AUGUR advisory system.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>MARSHAL — 5-Gate Evaluation</h3>
          {marshalGates.map(g => (
            <div key={g.number} style={{ display: 'flex', gap: 12, padding: '10px 0', borderBottom: '1px solid rgba(0,240,255,0.06)' }}>
              <div style={{
                width: 28, height: 28, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'rgba(0,240,255,0.1)', border: '1px solid rgba(0,240,255,0.2)',
                fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#00f0ff', fontWeight: 600, flexShrink: 0,
              }}>
                {g.number}
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{g.name}</div>
                <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>{g.description}</div>
              </div>
            </div>
          ))}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>WORM Chain</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Write-Once-Read-Many immutable audit log. SHA-256 hash chain with Ed25519 anchor rotation.
              Every governance decision is permanently recorded and tamper-detectable.
            </p>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>VIGIL</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Real-time health monitor. Background polling with mirror freshness tracking.
              Triggers alerts on degraded state across any connected platform.
            </p>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>AUGUR</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              Advisory system with ERP mirror reader. Real-time project state polling
              with staleness detection and rules engine.
            </p>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
