import ScrollSection from '../components/ScrollSection'
import PlatformCard from '../components/PlatformCard'
import { platforms, citadel } from '../data/platforms'

export default function PlatformsSection() {
  return (
    <ScrollSection id="platforms">
      <h2 className="section-title"><span className="gradient-text">Ecosystem</span> Platforms</h2>
      <p className="section-subtitle">
        {platforms.filter(p => p.status === 'active').length} active, {platforms.filter(p => p.status === 'planned').length} planned
        &mdash; all connected through <strong style={{ color: '#00f0ff', textShadow: '0 0 8px rgba(0,240,255,0.3)' }}>{citadel.name}</strong> governance.
      </p>
      <div className="grid-2">
        {platforms.map((p, i) => <PlatformCard key={p.id} platform={p} index={i} />)}
      </div>
    </ScrollSection>
  )
}
