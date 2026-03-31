import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html, Sparkles } from '@react-three/drei'
import * as THREE from 'three'

const LAYERS = [
  { code: 'L1', name: 'HW + TrustZone', color: '#ef4444', y: -1.8 },
  { code: 'L2', name: 'Radio (RIL)',     color: '#f59e0b', y: -1.1 },
  { code: 'L3', name: 'MVNO Stack',      color: '#10b981', y: -0.4 },
  { code: 'L4', name: 'CITADEL',         color: '#3b82f6', y:  0.3 },
  { code: 'L5', name: 'App Runtime',     color: '#7c3aed', y:  1.0 },
  { code: 'L6', name: 'User Interface',  color: '#00f0ff', y:  1.7 },
]

const MVNO_NODES = [
  { label: 'SIM',     angle: 0,              color: '#00f0ff' },
  { label: 'eSIM',    angle: Math.PI * 0.4,  color: '#10b981' },
  { label: 'VoIP',    angle: Math.PI * 0.8,  color: '#7c3aed' },
  { label: 'Roaming', angle: Math.PI * 1.2,  color: '#f59e0b' },
  { label: 'Policy',  angle: Math.PI * 1.6,  color: '#3b82f6' },
]

export default function MobileDevice() {
  const groupRef = useRef<THREE.Group>(null)
  const mvnoRef = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime()
    if (groupRef.current) {
      groupRef.current.rotation.y = Math.sin(t * 0.2) * 0.3
    }
    if (mvnoRef.current) {
      mvnoRef.current.rotation.y = t * 0.25
    }
  })

  return (
    <Float speed={0.8} rotationIntensity={0.08} floatIntensity={0.15}>
      <group ref={groupRef}>

        {/* Phone body wireframe */}
        <mesh>
          <boxGeometry args={[1.2, 2.4, 0.12]} />
          <meshStandardMaterial
            wireframe
            color="#334155"
            emissive="#334155"
            emissiveIntensity={0.2}
            transparent
            opacity={0.4}
          />
        </mesh>

        {/* Screen glass */}
        <mesh position={[0, 0, 0.07]}>
          <planeGeometry args={[1.0, 2.1]} />
          <meshStandardMaterial
            color="#0a1020"
            emissive="#0a1628"
            emissiveIntensity={0.1}
            transparent
            opacity={0.6}
          />
        </mesh>

        {/* Layer lines inside the phone */}
        {LAYERS.map(layer => (
          <group key={layer.code}>
            <mesh position={[0, layer.y * 0.5, 0.08]}>
              <planeGeometry args={[0.9, 0.02]} />
              <meshBasicMaterial color={layer.color} transparent opacity={0.6} toneMapped={false} />
            </mesh>
            <Html
              position={[0.65, layer.y * 0.5, 0.08]}
              center
              distanceFactor={8}
              style={{ pointerEvents: 'none', whiteSpace: 'nowrap' }}
            >
              <span style={{
                fontSize: 8, fontFamily: 'JetBrains Mono, monospace',
                color: layer.color, opacity: 0.8,
              }}>
                {layer.code}
              </span>
            </Html>
          </group>
        ))}

        {/* MVNO orbital ring at L3 height */}
        <group ref={mvnoRef} position={[0, LAYERS[2].y * 0.5, 0]}>
          {MVNO_NODES.map(node => {
            const r = 1.1
            const x = Math.cos(node.angle) * r
            const z = Math.sin(node.angle) * r
            return (
              <group key={node.label}>
                <mesh position={[x, 0, z]}>
                  <sphereGeometry args={[0.08, 16, 16]} />
                  <meshStandardMaterial
                    color={node.color}
                    emissive={node.color}
                    emissiveIntensity={0.6}
                    toneMapped={false}
                  />
                </mesh>
                <Html
                  position={[x, 0.2, z]}
                  center
                  distanceFactor={10}
                  style={{ pointerEvents: 'none', whiteSpace: 'nowrap' }}
                >
                  <span style={{
                    fontSize: 8, fontFamily: 'JetBrains Mono, monospace',
                    color: node.color, opacity: 0.8,
                  }}>
                    {node.label}
                  </span>
                </Html>
              </group>
            )
          })}
          {/* Orbit ring line */}
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[1.1, 0.008, 8, 64]} />
            <meshBasicMaterial color="#10b981" transparent opacity={0.2} />
          </mesh>
        </group>

        {/* ARM TrustZone glow at bottom */}
        <mesh position={[0, -1.0, 0]}>
          <sphereGeometry args={[0.12, 16, 16]} />
          <meshBasicMaterial color="#ef4444" toneMapped={false} />
        </mesh>

        <Sparkles count={30} scale={3} size={1} speed={0.15} color="#10b981" opacity={0.3} />
      </group>
    </Float>
  )
}
