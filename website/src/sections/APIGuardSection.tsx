import PlatformDetailSection, { ArchitectureCard, CapabilitiesCard, GradientTitle } from '../components/PlatformDetailSection'
import { apiGuardData as d } from '../data/platformSections'

export default function APIGuardSection() {
  return (
    <PlatformDetailSection
      id={d.id}
      title={<GradientTitle>{d.title}</GradientTitle>}
      subtitle={d.subtitle}
      left={<CapabilitiesCard heading={d.capabilitiesHeading} items={d.capabilities} accentColor={d.accentColor} />}
      right={<ArchitectureCard lines={d.archLines} />}
    />
  )
}
