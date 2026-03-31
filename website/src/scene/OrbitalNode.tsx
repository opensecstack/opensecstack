import { useRef, useState } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import type { Mesh } from 'three'
import type { Platform } from '../data/platforms'

interface Props {
  platform: Platform
  angle: number
  radius: number
}

export default function OrbitalNode({ platform, angle, radius }: Props) {
  const ref = useRef<Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(({ clock }) => {
    if (!ref.current) return
    const t = clock.getElapsedTime() * 0.08 + angle
    ref.current.position.x = Math.cos(t) * radius
    ref.current.position.z = Math.sin(t) * radius
    ref.current.position.y = Math.sin(t * 2) * 0.3
  })

  const isActive = platform.status === 'active'

  return (
    <mesh
      ref={ref}
      onPointerOver={() => setHovered(true)}
      onPointerOut={() => setHovered(false)}
      scale={hovered ? 1.3 : 1}
    >
      <sphereGeometry args={[0.25, 32, 32]} />
      <meshStandardMaterial
        color={platform.color}
        emissive={platform.color}
        emissiveIntensity={hovered ? 0.8 : isActive ? 0.4 : 0.15}
        transparent={!isActive}
        opacity={isActive ? 1 : 0.5}
      />
      {hovered && (
        <Html center distanceFactor={8} style={{ pointerEvents: 'none' }}>
          <div style={{
            background: 'rgba(13,13,31,0.9)',
            border: `1px solid ${platform.color}`,
            borderRadius: 8,
            padding: '6px 12px',
            whiteSpace: 'nowrap',
            fontSize: 13,
            fontFamily: 'Inter, sans-serif',
            color: '#e2e8f0',
          }}>
            <strong style={{ color: platform.color }}>{platform.name}</strong>
            <br />
            <span style={{ fontSize: 11, color: '#94a3b8' }}>{platform.tagline}</span>
          </div>
        </Html>
      )}
    </mesh>
  )
}
