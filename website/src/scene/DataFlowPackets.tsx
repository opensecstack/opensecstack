import { useRef, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'
import { platforms } from '../data/platforms'

const RADIUS = 4.5
const ORBIT_SPEED = 0.08
const step = (Math.PI * 2) / platforms.length
const TRIP_DURATION = 3 // seconds per trip

/**
 * Animated "data packet" spheres that travel along the WORM edges
 * from each orbital node toward the fortress center, then loop.
 */
export default function DataFlowPackets() {
  const meshRefs = useRef<(THREE.Mesh | null)[]>([])

  // Phase offsets so packets don't all arrive at the same time
  const phaseOffsets = useMemo(
    () => platforms.map((_, i) => (i / platforms.length) * TRIP_DURATION),
    [],
  )

  useFrame(({ clock }) => {
    const elapsed = clock.getElapsedTime()

    for (let i = 0; i < platforms.length; i++) {
      const mesh = meshRefs.current[i]
      if (!mesh) continue

      // Same orbital formula as OrbitalNode / WormChainEdges
      const t = elapsed * ORBIT_SPEED + step * i
      const nodeX = Math.cos(t) * RADIUS
      const nodeZ = Math.sin(t) * RADIUS
      const nodeY = Math.sin(t * 2) * 0.3

      // Progress along the trip (0 = at node, 1 = at center), then loop
      const progress =
        ((elapsed + phaseOffsets[i]) % TRIP_DURATION) / TRIP_DURATION

      // Lerp from node position to center [0,0,0]
      mesh.position.x = nodeX * (1 - progress)
      mesh.position.y = nodeY * (1 - progress)
      mesh.position.z = nodeZ * (1 - progress)

      // Pulse opacity: fade in at start, fade out near center
      const opacity = Math.sin(progress * Math.PI)
      const mat = mesh.material as THREE.MeshStandardMaterial
      mat.opacity = opacity * 0.9
    }
  })

  return (
    <group>
      {platforms.map((p, i) => (
        <mesh
          key={p.id}
          ref={(el) => {
            meshRefs.current[i] = el
          }}
        >
          <sphereGeometry args={[0.04, 12, 12]} />
          <meshStandardMaterial
            color={p.color}
            emissive={p.color}
            emissiveIntensity={2}
            transparent
            opacity={0.9}
          />
        </mesh>
      ))}
    </group>
  )
}
