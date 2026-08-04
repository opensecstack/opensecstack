import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { platforms } from '../data/platforms'
import { getOrbitPosition } from './orbitalMath'

const RADIUS = 4.5
const step = (Math.PI * 2) / platforms.length

/**
 * Animated lines from each orbital node to the fortress center.
 * Positions are recomputed every frame using the same formula
 * as OrbitalNode so the endpoints stay perfectly attached.
 */
export default function WormChainEdges() {
  const linesRef = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!linesRef.current) return
    const elapsed = clock.getElapsedTime()

    for (let i = 0; i < platforms.length; i++) {
      const line = linesRef.current.children[i] as THREE.Line
      if (!line) continue

      // Shared formula — see orbitalMath.ts. Kept in sync with OrbitalNode.tsx
      // (which also uses getOrbitPosition). DataFlowPackets.tsx still has its
      // own inline copy that should eventually be migrated too.
      const { x, y, z } = getOrbitPosition(elapsed, step * i, RADIUS)

      const positions = line.geometry.getAttribute('position')
      if (!positions) continue

      // Point 0: node position
      positions.setXYZ(0, x, y, z)
      // Point 1: fortress center
      positions.setXYZ(1, 0, 0, 0)
      positions.needsUpdate = true
    }
  })

  return (
    <group ref={linesRef}>
      {platforms.map((p) => (
        <line key={p.id}>
          <bufferGeometry>
            <bufferAttribute
              attach="attributes-position"
              count={2}
              array={new Float32Array([0, 0, 0, 0, 0, 0])}
              itemSize={3}
            />
          </bufferGeometry>
          <lineDashedMaterial
            color="#00f0ff"
            transparent
            opacity={0.25}
            dashSize={0.3}
            gapSize={0.15}
          />
        </line>
      ))}
    </group>
  )
}
