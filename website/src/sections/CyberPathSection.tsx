import PlatformDetailSection, { CapabilitiesCard, CardStack, GradientTitle, TextCard } from '../components/PlatformDetailSection'

const capabilities = [
  'Interactive labs', 'Skill assessments', 'Certification tracking',
  'ENISA framework alignment', 'Team progress dashboard', 'Custom curricula',
]

export default function CyberPathSection() {
  return (
    <PlatformDetailSection
      id="cyberpath"
      title={<GradientTitle>CyberPath</GradientTitle>}
      subtitle="Hands-on cybersecurity training platform with interactive labs, skill assessments, and certification tracking. Aligned with the cybersecurity skills framework from ENISA, the EU's cybersecurity agency."
      left={<CapabilitiesCard heading="Capabilities" items={capabilities} accentColor="#e040fb" />}
      right={
        <CardStack>
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
          <TextCard heading="SecureLab Integration">
            Live sandbox environments powered by SecureLab. Each lab runs
            in a CITADEL-governed container with isolated networking and auto-cleanup.
          </TextCard>
        </CardStack>
      }
    />
  )
}
