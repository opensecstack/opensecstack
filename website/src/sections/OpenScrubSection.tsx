import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'XDP/eBPF kernel-level packet filtering', 'GoBGP blackhole routing',
  'FastNetMon detection integration', 'Per-source rate limiting',
  'Allowlist/blocklist management', 'CITADEL-governed rule lifecycle',
]

export default function OpenScrubSection() {
  return (
    <ScrollSection id="openscrub">
      <h2 className="section-title"><span className="gradient-text">OpenScrub</span></h2>
      <p className="section-subtitle">
        Kernel-level DDoS mitigation. XDP/eBPF programs filter malicious traffic before it reaches
        the network stack, with GoBGP blackhole routing for volumetric attacks.
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
            <div><span className="tech-tag">Detect</span> FastNetMon flow analysis + threshold alerts</div>
            <div><span className="tech-tag">Filter</span> XDP/eBPF programs at kernel ingress</div>
            <div><span className="tech-tag">Blackhole</span> GoBGP RTBH announcements for volumetric</div>
            <div><span className="tech-tag">Block</span> ThreatFlow IOC auto-block integration</div>
            <div><span className="tech-tag">Validate</span> SecureLab DDoS rule simulation</div>
            <div><span className="tech-tag">Audit</span> CITADEL WORM chain for all rule changes</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
