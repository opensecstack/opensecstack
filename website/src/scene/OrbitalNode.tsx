import { useRef, useState, useCallback } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'
import type { Platform } from '../data/platforms'

interface Props {
  platform: Platform
  angle: number
  radius: number
}

export default function OrbitalNode({ platform, angle, radius }: Props) {
  const ref = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(({ clock }) => {
    if (!ref.current) return
    const t = clock.getElapsedTime() * 0.08 + angle
    ref.current.position.x = Math.cos(t) * radius
    ref.current.position.z = Math.sin(t) * radius
    ref.current.position.y = Math.sin(t * 2) * 0.3

    // Smooth scale lerp
    const target = hovered ? 1.4 : 1
    ref.current.scale.lerp(new THREE.Vector3(target, target, target), 0.1)
  })

  const isActive = platform.status === 'active'

  const onOver = useCallback(() => {
    setHovered(true)
    document.body.style.cursor = 'pointer'
  }, [])

  const onOut = useCallback(() => {
    setHovered(false)
    document.body.style.cursor = 'auto'
  }, [])

  return (
    <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut}>
      <sphereGeometry args={[0.3, 32, 32]} />
      <meshStandardMaterial
        color={platform.color}
        emissive={platform.color}
        emissiveIntensity={hovered ? 1.0 : isActive ? 0.4 : 0.15}
        transparent={!isActive}
        opacity={isActive ? 1 : 0.5}
        toneMapped={false}
      />
      {/* Always render the label — visibility controlled by opacity */}
      <Html
        center
        distanceFactor={8}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s ease',
          opacity: hovered ? 1 : 0,
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: `1px solid ${platform.color}`,
          borderRadius: 10,
          padding: '8px 16px',
          whiteSpace: 'nowrap',
          fontSize: 14,
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: `0 0 20px ${platform.color}44`,
          transform: 'translateY(-20px)',
        }}>
          <strong style={{ color: platform.color }}>{platform.name}</strong>
          <br />
          <span style={{ fontSize: 11, color: '#94a3b8' }}>{platform.tagline}</span>
          <span style={{
            display: 'inline-block', marginLeft: 8,
            fontSize: 10, padding: '1px 6px', borderRadius: 4,
            background: isActive ? 'rgba(16,185,129,0.2)' : 'rgba(148,163,184,0.1)',
            color: isActive ? '#10b981' : '#94a3b8',
          }}>
            {platform.status}
          </span>
        </div>
      </Html>
    </mesh>
  )
}
