import { useRef, useState, useCallback } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html } from '@react-three/drei'
import { marshalGates } from '../data/marshalGates'
import { useHoverScale } from '../hooks/useHoverScale'
import type { Mesh } from 'three'

export default function CitadelFortress() {
  const ref = useRef<Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(() => {
    if (!ref.current) return
    ref.current.rotation.y += hovered ? 0.008 : 0.002
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(ref, hovered, 1.15, 8)

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut}>
        <icosahedronGeometry args={[1.4, 1]} />
        <meshStandardMaterial
          wireframe
          color="#00f0ff"
          emissive="#00f0ff"
          emissiveIntensity={hovered ? 0.9 : 0.3}
          transparent
          opacity={hovered ? 1 : 0.85}
          toneMapped={false}
        />
      </mesh>

      <Html
        center
        distanceFactor={6}
        position={[0, 2.2, 0]}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.25s ease, transform 0.25s ease',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateY(0)' : 'translateY(8px)',
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: '1px solid #00f0ff',
          borderRadius: 12,
          padding: '12px 20px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: '0 0 30px rgba(0,240,255,0.25)',
          textAlign: 'center',
          minWidth: 220,
        }}>
          <div style={{ fontSize: 18, fontWeight: 700, color: '#00f0ff', letterSpacing: '0.1em' }}>
            CITADEL
          </div>
          <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
            Governance Engine
          </div>
          <div style={{ marginTop: 10, display: 'flex', gap: 6, justifyContent: 'center' }}>
            {marshalGates.map(g => (
              <div key={g.number} title={g.name} style={{
                width: 28, height: 28, borderRadius: 6,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'rgba(0,240,255,0.1)',
                border: '1px solid rgba(0,240,255,0.25)',
                fontSize: 11, fontWeight: 600, color: '#00f0ff',
                fontFamily: 'JetBrains Mono, monospace',
              }}>
                G{g.number}
              </div>
            ))}
          </div>
          <div style={{ fontSize: 10, color: '#64748b', marginTop: 6 }}>
            MARSHAL 5-Gate &middot; WORM Chain &middot; VIGIL
          </div>
        </div>
      </Html>
    </Float>
  )
}
