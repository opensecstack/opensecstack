import ScrollSection from '../components/ScrollSection'

const capabilities = [
  'Prompt injection detection (OWASP LLM Top 10)', 'Deepfake video/voice detection',
  'C2PA media authenticity verification', 'AI threat intelligence feed (MITRE ATLAS)',
  'Real-time WebSocket video stream analysis', 'Zoom / Teams / WebEx plugins',
]

export default function VertGuardSection() {
  return (
    <ScrollSection id="vertguard">
      <h2 className="section-title"><span className="gradient-text">VertGuard</span></h2>
      <p className="section-subtitle">
        AI-attack defence platform. Detects prompt injection, deepfakes, and synthetic media at
        inference time — feeding high-confidence detections directly into IRFlow and CITADEL.
      </p>
      <div className="grid-2">
        <div className="glass-card">
          <h3 style={{ marginBottom: '1rem', fontSize: '1.1rem' }}>Capabilities</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            {capabilities.map(c => (
              <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.85rem' }}>
                <span style={{ color: '#f97316' }}>&#10003;</span> {c}
              </div>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Five Modules</h3>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
              <div><span className="tech-tag">Module 1</span> Media Authenticity — C2PA + deepfake ML</div>
              <div><span className="tech-tag">Module 2</span> AI Phishing Detection</div>
              <div><span className="tech-tag">Module 3</span> Prompt Injection Defence (OWASP LLM Top 10)</div>
              <div><span className="tech-tag">Module 4</span> AI Threat Intel Feed (MITRE ATLAS)</div>
              <div><span className="tech-tag">Module 5</span> Synthetic Identity Detection</div>
            </div>
          </div>
          <div className="glass-card">
            <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>Ecosystem Integration</h3>
            <p style={{ fontSize: '0.85rem', color: '#94a3b8', lineHeight: 1.6 }}>
              HIGH-confidence detections auto-create incidents in IRFlow.
              AI-specific IOCs feed ThreatFlow. Evidence envelopes (C2PA + JSON)
              are anchored in the CITADEL WORM chain. Cross-border AI attack
              patterns are shared via OpenCSIRT.
            </p>
          </div>
        </div>
      </div>
    </ScrollSection>
  )
}
