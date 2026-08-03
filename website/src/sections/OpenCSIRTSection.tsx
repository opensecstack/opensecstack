import PlatformDetailSection, { CapabilitiesCard, CardStack, GradientTitle, TextCard } from '../components/PlatformDetailSection'

const capabilities = [
  'Multi-CSIRT coordination', 'NIS2 incident reporting (24h/72h)', 'Cross-border sharing',
  'Vulnerability disclosure', 'Situational awareness', 'EU-wide dashboard',
]

export default function OpenCSIRTSection() {
  return (
    <PlatformDetailSection
      id="opencsirt"
      title={<GradientTitle>OpenCSIRT</GradientTitle>}
      subtitle="Computer Security Incident Response Team operations platform for EU member states. Cross-border incident coordination aligned with NIS2 Directive reporting requirements."
      left={<CapabilitiesCard heading="Capabilities" items={capabilities} accentColor="#8b5cf6" />}
      right={
        <CardStack>
          <TextCard heading="NIS2 Reporting">
            Automated 24-hour early warning and 72-hour incident notification
            for national competent authorities. Template-driven reporting aligned
            with ENISA incident taxonomy.
          </TextCard>
          <TextCard heading="Cross-Border Coordination">
            Shared IOC feeds via ThreatFlow TAXII. Multi-CSIRT incident
            handoff with hash-linked evidence chain. EU-CyCLONe integration
            for large-scale crisis management.
          </TextCard>
          <TextCard heading="Vulnerability Disclosure">
            Coordinated vulnerability disclosure (CVD) platform. Researcher
            submission portal, triage workflow, and public advisory publishing
            with CVSS scoring from APIGuard.
          </TextCard>
        </CardStack>
      }
    />
  )
}
