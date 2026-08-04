import PlatformDetailSection, { CapabilitiesCard, CardStack, GradientTitle, TextCard } from '../components/PlatformDetailSection'

const capabilities = [
  'Prompt injection detection (OWASP LLM Top 10)', 'Deepfake video/voice detection',
  'C2PA media authenticity verification', 'AI threat intelligence feed (MITRE ATLAS)',
  'Real-time WebSocket video stream analysis', 'Zoom / Teams / WebEx plugins',
]

export default function VertGuardSection() {
  return (
    <PlatformDetailSection
      id="vertguard"
      title={<GradientTitle>VertGuard</GradientTitle>}
      subtitle="AI-attack defence platform. Detects prompt injection, deepfakes, and synthetic media at inference time."
      left={<CapabilitiesCard heading="Capabilities" items={capabilities} accentColor="#f97316" />}
      right={
        <CardStack>
          <div className="glass-card">
            <h3 className="card-title" style={{ marginBottom: '0.5rem' }}>Five Modules</h3>
            <div style={{ fontFamily: 'var(--mono)', fontSize: '0.8rem', color: '#94a3b8', lineHeight: 2 }}>
              <div><span className="tech-tag">Module 1</span> Media Authenticity — C2PA + deepfake ML</div>
              <div><span className="tech-tag">Module 2</span> AI Phishing Detection</div>
              <div><span className="tech-tag">Module 3</span> Prompt Injection Defence (OWASP LLM Top 10)</div>
              <div><span className="tech-tag">Module 4</span> AI Threat Intel Feed (MITRE ATLAS)</div>
              <div><span className="tech-tag">Module 5</span> Synthetic Identity Detection</div>
            </div>
          </div>
          <TextCard heading="Ecosystem Integration">
            HIGH-confidence detections auto-create incidents in IRFlow.
            AI-specific IOCs feed ThreatFlow. Evidence envelopes (C2PA + JSON)
            are anchored in the CITADEL WORM chain. Cross-border AI attack
            patterns are shared via OpenCSIRT.
          </TextCard>
        </CardStack>
      }
    />
  )
}
