import { useEffect, useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'

/**
 * Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx /
 * WormChainVisual.tsx: continuous decorative animation is frozen (not just
 * slowed) when the user has requested reduced motion, while the static
 * lanes and labels remain fully visible.
 */
function usePrefersReducedMotion(): boolean {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => setReduced(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])
  return reduced
}

const CYAN = '#00f0ff'
const VIOLET = '#7c3aed'
const MAGENTA = '#e040fb'

const INPUT_X = -3.4
const OUTPUT_X = 3.4
const LANE_LENGTH = OUTPUT_X - INPUT_X

interface LaneData {
  name: string
  color: string
  y: number
  /** Seconds for one packet to travel the full lane — deliberately distinct
   * per lane so the three algorithms visibly don't lock-step, illustrating
   * "independent" processing rather than a shared clock. */
  duration: number
  /** Phase offset (0..1 of duration) so packets don't all launch at once. */
  phase: number
}

const LANES: LaneData[] = [
  { name: 'SHA-256', color: CYAN, y: 0.9, duration: 1.6, phase: 0 },
  { name: 'SHA-512', color: VIOLET, y: 0, duration: 1.9, phase: 0.33 },
  { name: 'BLAKE3', color: MAGENTA, y: -0.9, duration: 1.1, phase: 0.66 },
]

// Illustrative/fake composite digest only — purely decorative, not a real
// live-computed hash of anything.
const FAKE_COMPOSITE_HASH = 'a3f2c9…9c1e'

interface LaneProps {
  lane: LaneData
  reducedMotion: boolean
}

/** A single static lane (line + endpoints) connecting input to output. */
function Lane({ lane }: { lane: LaneData }) {
  const positions = useMemo(
    () => new Float32Array([INPUT_X, lane.y, 0, OUTPUT_X, lane.y, 0]),
    [lane.y],
  )

  return (
    <group>
      <line>
        <bufferGeometry>
          <bufferAttribute
            attach="attributes-position"
            count={2}
            array={positions}
            itemSize={3}
          />
        </bufferGeometry>
        <lineBasicMaterial color={lane.color} transparent opacity={0.45} toneMapped={false} />
      </line>

      <Html
        center
        distanceFactor={7}
        position={[INPUT_X + LANE_LENGTH * 0.5, lane.y + 0.32, 0]}
        style={{ pointerEvents: 'none' }}
      >
        <div
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 11,
            fontWeight: 700,
            color: lane.color,
            whiteSpace: 'nowrap',
            letterSpacing: '0.04em',
          }}
        >
          {lane.name}
        </div>
      </Html>
    </group>
  )
}

/** Small animated sphere traveling along one lane, looping continuously. */
function LanePacket({ lane, reducedMotion }: LaneProps) {
  const meshRef = useRef<THREE.Mesh>(null)

  useFrame(({ clock }) => {
    const mesh = meshRef.current
    if (!mesh) return

    if (reducedMotion) {
      mesh.visible = false
      return
    }
    mesh.visible = true

    const t = ((clock.getElapsedTime() / lane.duration + lane.phase) % 1)
    mesh.position.x = THREE.MathUtils.lerp(INPUT_X, OUTPUT_X, t)
    mesh.position.y = lane.y
    mesh.position.z = 0

    // Fade in/out near the endpoints so packets don't visually "pop".
    const fade = Math.sin(t * Math.PI)
    const mat = mesh.material as THREE.MeshStandardMaterial
    mat.opacity = 0.4 + fade * 0.6
  })

  return (
    <mesh ref={meshRef}>
      <sphereGeometry args={[0.09, 12, 12]} />
      <meshStandardMaterial
        color={lane.color}
        emissive={lane.color}
        emissiveIntensity={1.8}
        transparent
        opacity={0.9}
        toneMapped={false}
      />
    </mesh>
  )
}

/** The single input block on the left, representing the raw audit-log entry. */
function InputNode() {
  return (
    <group position={[INPUT_X, 0, 0]}>
      <mesh>
        <boxGeometry args={[0.6, 2.2, 0.5]} />
        <meshStandardMaterial
          color="#94a3b8"
          emissive="#94a3b8"
          emissiveIntensity={0.25}
          transparent
          opacity={0.75}
          toneMapped={false}
        />
      </mesh>
      <Html center distanceFactor={7} position={[0, -1.5, 0]} style={{ pointerEvents: 'none' }}>
        <div
          style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 11,
            fontWeight: 600,
            color: '#e2e8f0',
            whiteSpace: 'nowrap',
          }}
        >
          Entry data
        </div>
        <div style={{ fontFamily: 'Inter, sans-serif', fontSize: 9, color: '#64748b', marginTop: 2 }}>
          Input
        </div>
      </Html>
    </group>
  )
}

/** The single combined output block on the right, representing the composite digest. */
function OutputNode() {
  return (
    <group position={[OUTPUT_X, 0, 0]}>
      <mesh>
        <boxGeometry args={[0.6, 2.2, 0.5]} />
        <meshStandardMaterial
          color={CYAN}
          emissive={CYAN}
          emissiveIntensity={0.5}
          transparent
          opacity={0.85}
          toneMapped={false}
        />
      </mesh>
      <Html center distanceFactor={7} position={[0, -1.5, 0]} style={{ pointerEvents: 'none' }}>
        <div
          style={{
            fontFamily: 'Inter, sans-serif',
            fontSize: 11,
            fontWeight: 700,
            color: CYAN,
            whiteSpace: 'nowrap',
          }}
        >
          TripleHash
        </div>
        <div style={{ fontFamily: 'Inter, sans-serif', fontSize: 9, color: '#94a3b8', marginTop: 2 }}>
          Composite digest
        </div>
        <div
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 10,
            color: '#5b6579',
            marginTop: 4,
          }}
        >
          {FAKE_COMPOSITE_HASH}
        </div>
      </Html>

      {/* Illustrative-only reference figure, explicitly not a live measurement. */}
      <Html center distanceFactor={7} position={[0, 1.75, 0]} style={{ pointerEvents: 'none' }}>
        <div
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 9,
            color: '#64748b',
            whiteSpace: 'nowrap',
          }}
        >
          reference: ~1.5&nbsp;µs / 100B payload
        </div>
      </Html>
    </group>
  )
}

interface SceneProps {
  reducedMotion: boolean
}

function Scene({ reducedMotion }: SceneProps) {
  return (
    <>
      <ambientLight intensity={0.2} />
      <pointLight position={[6, 6, 6]} intensity={0.35} color={CYAN} />
      <pointLight position={[-6, -3, -4]} intensity={0.2} color={VIOLET} />

      <InputNode />
      {LANES.map((lane) => (
        <Lane key={lane.name} lane={lane} />
      ))}
      {LANES.map((lane) => (
        <LanePacket key={lane.name} lane={lane} reducedMotion={reducedMotion} />
      ))}
      <OutputNode />
    </>
  )
}

export interface TripleHashVisualProps {
  className?: string
}

/**
 * Self-contained 3D illustration of CITADEL's TripleHash mechanism: a single
 * "Entry data" input flows into three parallel, independently-timed lanes —
 * SHA-256, SHA-512 and BLAKE3 — which converge into one "TripleHash"
 * composite-digest output.
 *
 * The composite hash string and the "reference: ~1.5µs/100B" note shown near
 * the output are illustrative placeholders, not a live computation — real
 * benchmark figures live in project docs. Drop this anywhere — it renders its
 * own <Canvas> and needs no props to be meaningful.
 */
export default function TripleHashVisual({ className }: TripleHashVisualProps) {
  const reducedMotion = usePrefersReducedMotion()

  return (
    <div className={className} style={{ width: '100%', height: '100%', minHeight: 240 }}>
      <Canvas
        camera={{ position: [0, 0, 7], fov: 45 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <Scene reducedMotion={reducedMotion} />
      </Canvas>
    </div>
  )
}
