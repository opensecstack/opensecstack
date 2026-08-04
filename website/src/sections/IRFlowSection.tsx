import PlatformDetailSection, { CapabilitiesCard, CardStack, FlowStepsCard, GradientTitle, TextCard } from '../components/PlatformDetailSection'

const capabilities = [
  'Playbook automation', 'Evidence chain (hash-linked)', 'SLA tracking',
  'Stakeholder notifications', 'Post-mortem reports', 'CSIRT coordination',
]

export default function IRFlowSection() {
  return (
    <PlatformDetailSection
      id="irflow"
      title={<GradientTitle>IRFlow</GradientTitle>}
      subtitle="Structured incident response platform for your own security team, covering the full lifecycle from detection to post-mortem with automated playbooks and an evidence chain — including the NIS2-mandated 24h/72h notification steps."
      left={<CapabilitiesCard heading="Capabilities" items={capabilities} accentColor="#f59e0b" />}
      right={
        <CardStack>
          <FlowStepsCard
            heading="Incident Lifecycle"
            steps={['Detection', 'Triage', 'Containment', 'Eradication', 'Recovery', 'Post-mortem']}
            color="#f59e0b"
          />
          <TextCard heading="Evidence Chain">
            Every incident artefact is hash-linked into an immutable evidence chain.
            CITADEL WORM log provides tamper-proof custody trail for regulatory proof.
          </TextCard>
          <TextCard heading="NIS2 Reporting">
            Automated 24-hour early warning and 72-hour incident notification
            aligned with NIS2 Directive Article 23 reporting obligations.
          </TextCard>
        </CardStack>
      }
    />
  )
}
