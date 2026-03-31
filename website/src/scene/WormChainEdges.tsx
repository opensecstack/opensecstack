import { Line } from '@react-three/drei'
import { platforms } from '../data/platforms'

const RADIUS = 4.5

export default function WormChainEdges() {
  const step = (Math.PI * 2) / platforms.length

  return (
    <group>
      {platforms.map((p, i) => {
        const angle = step * i
        const points: Array<[number, number, number]> = [
          [Math.cos(angle) * RADIUS, 0, Math.sin(angle) * RADIUS],
          [0, 0, 0],
        ]
        return (
          <Line
            key={p.id}
            points={points}
            color="#00f0ff"
            lineWidth={1}
            transparent
            opacity={0.25}
            dashed
            dashSize={0.3}
            gapSize={0.15}
          />
        )
      })}
    </group>
  )
}
