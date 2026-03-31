import OrbitalNode from './OrbitalNode'
import { platforms } from '../data/platforms'

const RADIUS = 4.5

export default function OrbitalRing() {
  const step = (Math.PI * 2) / platforms.length

  return (
    <group>
      {platforms.map((p, i) => (
        <OrbitalNode key={p.id} platform={p} angle={step * i} radius={RADIUS} />
      ))}
    </group>
  )
}
