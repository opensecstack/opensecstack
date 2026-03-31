import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'IOC feed aggregation', 'TTP mapping (MITRE ATT&CK)', 'STIX 2.1 bundles',
  'TAXII 2.1 server', 'Automated correlation', 'Alert scoring',
]

export default function ThreatFlowSection() {
  return (
    <ScrollSection id="threatflow">
      <h2 className="section-title"><span className="gradient-text">ThreatFlow</span></h2>
      <p className="section-subtitle">
        Real-time threat intelligence platform. IOC ingestion, correlation, and STIX/TAXII sharing for threat-informed defence.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#ef4444' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Architecture</h3>
          <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
            <div><span className="tech-tag">Ingest</span> Multi-source IOC feed aggregation</div>
            <div><span className="tech-tag">Correlate</span> TTP mapping against MITRE ATT&amp;CK</div>
            <div><span className="tech-tag">Share</span> STIX 2.1 bundles via TAXII 2.1</div>
            <div><span className="tech-tag">Score</span> Threat scoring with confidence levels</div>
            <div><span className="tech-tag">Integrate</span> APIGuard, IRFlow, NIS2 Compass feeds</div>
            <div><span className="tech-tag">Audit</span> CITADEL WORM chain for all events</div>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
