import { useRef, useState, useCallback, useMemo } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html } from '@react-three/drei'
import * as THREE from 'three'
import { marshalGates } from '../data/marshalGates'
import { useHoverScale } from '../hooks/useHoverScale'
import { useLowPowerDevice } from '../hooks/useLowPowerDevice'
import type { Group, Mesh } from 'three'

const ICOSAHEDRON_RADIUS = 1.4
const ICOSAHEDRON_DETAIL = 1
/** Particles sampled per edge of the (subdivided) icosahedron -- ~120 edges
 * at detail=1, so this yields roughly 1000-1500 points total: dense enough
 * to read as a glowing point-cloud tracing the shape (matching the "Vertex
 * 4023"-style reference), while staying a single cheap Points draw call. */
const PARTICLES_PER_EDGE = 10

/**
 * Builds a point cloud tracing every edge of an icosahedron (radius/detail
 * matching the wireframe mesh below), with a small amount of jitter so it
 * reads as an organic glowing point-field rather than perfectly straight
 * lines of dots. Computed once (geometry/detail never change at runtime),
 * so the one-time THREE.EdgesGeometry allocation here is not a per-frame
 * concern.
 */
function buildEdgeParticlePositions(radius: number, detail: number, perEdge: number): Float32Array {
  const base = new THREE.IcosahedronGeometry(radius, detail)
  const edges = new THREE.EdgesGeometry(base)
  const posAttr = edges.getAttribute('position')
  const points: number[] = []
  const a = new THREE.Vector3()
  const b = new THREE.Vector3()

  for (let i = 0; i < posAttr.count; i += 2) {
    a.fromBufferAttribute(posAttr, i)
    b.fromBufferAttribute(posAttr, i + 1)
    for (let k = 0; k < perEdge; k++) {
      const t = perEdge > 1 ? k / (perEdge - 1) : 0
      const jitter = () => (Math.random() - 0.5) * 0.025
      points.push(
        THREE.MathUtils.lerp(a.x, b.x, t) + jitter(),
        THREE.MathUtils.lerp(a.y, b.y, t) + jitter(),
        THREE.MathUtils.lerp(a.z, b.z, t) + jitter(),
      )
    }
  }

  base.dispose()
  edges.dispose()
  return new Float32Array(points)
}

interface EdgeParticlesProps {
  hovered: boolean
}

/** The dense glowing point-cloud layered over the wireframe hub, skipped entirely on low-power devices. */
function EdgeParticles({ hovered }: EdgeParticlesProps) {
  const positions = useMemo(
    () => buildEdgeParticlePositions(ICOSAHEDRON_RADIUS, ICOSAHEDRON_DETAIL, PARTICLES_PER_EDGE),
    [],
  )
  const materialRef = useRef<THREE.PointsMaterial>(null)

  useFrame((_state, delta) => {
    const mat = materialRef.current
    if (!mat) return
    const targetOpacity = hovered ? 1 : 0.75
    mat.opacity = THREE.MathUtils.damp(mat.opacity, targetOpacity, 8, delta)
  })

  return (
    <points>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" count={positions.length / 3} array={positions} itemSize={3} />
      </bufferGeometry>
      <pointsMaterial
        ref={materialRef}
        color="#8be9ff"
        size={0.028}
        sizeAttenuation
        transparent
        opacity={0.75}
        blending={THREE.AdditiveBlending}
        depthWrite={false}
        toneMapped={false}
      />
    </points>
  )
}

export default function CitadelFortress() {
  const groupRef = useRef<Group>(null)
  const meshRef = useRef<Mesh>(null)
  const [hovered, setHovered] = useState(false)
  const lowPower = useLowPowerDevice()

  useFrame(() => {
    if (!groupRef.current) return
    groupRef.current.rotation.y += hovered ? 0.008 : 0.002
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(groupRef, hovered, 1.15, 8)

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <group ref={groupRef}>
        <mesh ref={meshRef} onPointerOver={onOver} onPointerOut={onOut}>
          <icosahedronGeometry args={[ICOSAHEDRON_RADIUS, ICOSAHEDRON_DETAIL]} />
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

        {!lowPower && <EdgeParticles hovered={hovered} />}

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
              MARSHAL 5-Gate &middot; WORM Chain &middot; AUGUR
            </div>
          </div>
        </Html>
      </group>
    </Float>
  )
}
