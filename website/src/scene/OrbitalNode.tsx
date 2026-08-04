import { useRef, useState, useCallback } from 'react'
import { useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import type { Mesh } from 'three'
import type { Platform } from '../data/platforms'
import { useHoverScale } from '../hooks/useHoverScale'
import { getOrbitPosition } from './orbitalMath'

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
    const { x, y, z } = getOrbitPosition(clock.getElapsedTime(), angle, radius)
    ref.current.position.set(x, y, z)
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(ref, hovered, 1.4, 8)

  const isActive = platform.status === 'active'

  const onOver = useCallback(() => {
    setHovered(true)
    document.body.style.cursor = 'pointer'
  }, [])

  const onOut = useCallback(() => {
    setHovered(false)
    document.body.style.cursor = 'auto'
  }, [])

  const onClick = useCallback(() => {
    const el = document.getElementById(platform.sectionId)
    if (el) el.scrollIntoView({ behavior: 'smooth' })
  }, [platform.sectionId])

  return (
    <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut} onClick={onClick}>
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
          <br />
          <span style={{ fontSize: 10, color: '#5b6579' }}>Click to view →</span>
        </div>
      </Html>
    </mesh>
  )
}
