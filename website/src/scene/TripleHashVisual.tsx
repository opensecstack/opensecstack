import { useEffect, useRef, useState, useCallback } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Float, Html } from '@react-three/drei'
import * as THREE from 'three'
import { useHoverScale } from '../hooks/useHoverScale'
import { getOrbitPosition } from './orbitalMath'

/**
 * Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx /
 * WormChainVisual.tsx: continuous decorative animation is frozen (not just
 * slowed) when the user has requested reduced motion, while the hub, the
 * 3 orbiting nodes and their labels remain fully, statically visible.
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

// Same established brand palette used elsewhere in the codebase
// (see index.css --cyan/--violet/--magenta and data/platforms.ts).
const CYAN = '#00f0ff'
const VIOLET = '#7c3aed'
const MAGENTA = '#e040fb'
// Distinct accent for the hub so it reads apart from the 3 algorithm nodes,
// while still drawn from the existing palette (data/platforms.ts amber).
const HUB_COLOR = '#f59e0b'

const RADIUS = 2.3

// Illustrative/fake composite digest only — purely decorative, not a real
// live-computed hash of anything.
const FAKE_COMPOSITE_HASH = 'a3f2c9…9c1e'

// Periodic convergence cycle: every CYCLE_DURATION seconds, the last
// (1 - CONVERGE_START) fraction of the cycle is the "convergence window"
// where the 3 node pulses travel inward and the hub flashes.
const CYCLE_DURATION = 3.6
const CONVERGE_START = 0.82

/** 0..1 position within the current animation cycle. */
function cyclePhase(elapsed: number): number {
  return (elapsed % CYCLE_DURATION) / CYCLE_DURATION
}

/** 0..1 linear progress through the convergence window, 0 outside of it. */
function convergenceRaw(phase: number): number {
  if (phase < CONVERGE_START) return 0
  return (phase - CONVERGE_START) / (1 - CONVERGE_START)
}

/** Triangular 0→1→0 envelope over the convergence window, for fades/flashes. */
function convergenceEnvelope(raw: number): number {
  return Math.sin(Math.min(raw, 1) * Math.PI)
}

interface AlgoConfig {
  name: string
  description: string
  color: string
  angle: number
  /** Distinct pulse frequency/phase per node so the three visibly desync,
   * illustrating independent concurrent processing rather than a shared clock. */
  freq: number
  phase: number
}

const ALGOS: AlgoConfig[] = [
  { name: 'SHA-256', description: 'NIST digest', color: CYAN, angle: 0, freq: 2.1, phase: 0 },
  { name: 'SHA-512', description: 'NIST digest (wide)', color: VIOLET, angle: (Math.PI * 2) / 3, freq: 1.4, phase: 1.1 },
  { name: 'BLAKE3', description: 'Tree-hash digest', color: MAGENTA, angle: (Math.PI * 4) / 3, freq: 2.8, phase: 2.4 },
]

interface AlgoNodeProps {
  algo: AlgoConfig
  reducedMotion: boolean
}

/** One orbiting sphere representing a single hash algorithm, independently
 * pulsing while it orbits the central hub. */
function AlgoNode({ algo, reducedMotion }: AlgoNodeProps) {
  const ref = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(({ clock }) => {
    const mesh = ref.current
    if (!mesh) return

    const elapsed = clock.getElapsedTime()
    const { x, y, z } = getOrbitPosition(reducedMotion ? 0 : elapsed, algo.angle, RADIUS)
    mesh.position.set(x, y, z)

    const pulse = reducedMotion
      ? 0.4
      : 0.4 + 0.4 * (0.5 + 0.5 * Math.sin(elapsed * algo.freq + algo.phase))
    const mat = mesh.material as THREE.MeshStandardMaterial
    mat.emissiveIntensity = hovered ? 1.0 : pulse
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(ref, hovered, 1.4, 8)

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut}>
      <sphereGeometry args={[0.28, 32, 32]} />
      <meshStandardMaterial
        color={algo.color}
        emissive={algo.color}
        emissiveIntensity={0.4}
        toneMapped={false}
      />

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
          border: `1px solid ${algo.color}`,
          borderRadius: 10,
          padding: '8px 14px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: `0 0 20px ${algo.color}44`,
          transform: 'translateY(-20px)',
          textAlign: 'center',
        }}>
          <strong style={{ color: algo.color }}>{algo.name}</strong>
          <br />
          <span style={{ fontSize: 11, color: '#94a3b8' }}>{algo.description}</span>
        </div>
      </Html>
    </mesh>
  )
}

interface ConvergencePulseProps {
  algo: AlgoConfig
  reducedMotion: boolean
}

/** A small particle that travels from one algorithm node inward to the hub
 * during the periodic convergence window, representing that node's digest
 * arriving to be combined into the composite hash. */
function ConvergencePulse({ algo, reducedMotion }: ConvergencePulseProps) {
  const ref = useRef<THREE.Mesh>(null)

  useFrame(({ clock }) => {
    const mesh = ref.current
    if (!mesh) return

    if (reducedMotion) {
      mesh.visible = false
      return
    }

    const elapsed = clock.getElapsedTime()
    const raw = convergenceRaw(cyclePhase(elapsed))
    if (raw <= 0) {
      mesh.visible = false
      return
    }
    mesh.visible = true

    const { x, y, z } = getOrbitPosition(elapsed, algo.angle, RADIUS)
    const remaining = 1 - raw
    mesh.position.set(x * remaining, y * remaining, z * remaining)

    const mat = mesh.material as THREE.MeshStandardMaterial
    mat.opacity = convergenceEnvelope(raw)
  })

  return (
    <mesh ref={ref} visible={false}>
      <sphereGeometry args={[0.11, 12, 12]} />
      <meshStandardMaterial
        color={algo.color}
        emissive={algo.color}
        emissiveIntensity={2}
        transparent
        opacity={0}
        toneMapped={false}
      />
    </mesh>
  )
}

interface HubProps {
  reducedMotion: boolean
}

/** The central hub: represents both the raw entry data going in and, on each
 * convergence flash, the composite TripleHash digest coming out. Mirrors
 * CitadelFortress's wireframe-icosahedron-with-emissive-glow language. */
function Hub({ reducedMotion }: HubProps) {
  const meshRef = useRef<THREE.Mesh>(null)
  const labelRef = useRef<HTMLDivElement>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(({ clock }) => {
    const mesh = meshRef.current
    if (!mesh) return

    if (!reducedMotion) {
      mesh.rotation.y += hovered ? 0.006 : 0.002
    }

    const elapsed = clock.getElapsedTime()
    const raw = reducedMotion ? 0 : convergenceRaw(cyclePhase(elapsed))
    const envelope = reducedMotion ? 0 : convergenceEnvelope(raw)

    const mat = mesh.material as THREE.MeshStandardMaterial
    mat.emissiveIntensity = (hovered ? 0.9 : 0.35) + envelope * 0.9

    if (labelRef.current) {
      labelRef.current.style.opacity = reducedMotion ? '1' : envelope > 0.05 ? String(envelope) : '0'
    }
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(meshRef, hovered, 1.15, 8)

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={meshRef} onPointerOver={onOver} onPointerOut={onOut}>
        <icosahedronGeometry args={[1, 1]} />
        <meshStandardMaterial
          wireframe
          color={HUB_COLOR}
          emissive={HUB_COLOR}
          emissiveIntensity={0.35}
          transparent
          opacity={hovered ? 1 : 0.85}
          toneMapped={false}
        />
      </mesh>

      {/* Periodic "digests converged" readout — statically visible under
          reduced motion instead of cycling. */}
      <Html center distanceFactor={7} position={[0, 1.55, 0]} style={{ pointerEvents: 'none' }}>
        <div
          ref={labelRef}
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 11,
            fontWeight: 700,
            color: HUB_COLOR,
            whiteSpace: 'nowrap',
            opacity: reducedMotion ? 1 : 0,
            transition: reducedMotion ? undefined : 'opacity 0.15s linear',
          }}
        >
          TripleHash: {FAKE_COMPOSITE_HASH}
        </div>
      </Html>

      {/* Hover tooltip, matching CitadelFortress's tooltip visual style. */}
      <Html
        center
        distanceFactor={6}
        position={[0, -1.55, 0]}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.25s ease, transform 0.25s ease',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateY(0)' : 'translateY(8px)',
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: `1px solid ${HUB_COLOR}`,
          borderRadius: 12,
          padding: '10px 18px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: `0 0 30px ${HUB_COLOR}44`,
          textAlign: 'center',
        }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: HUB_COLOR, letterSpacing: '0.06em' }}>
            TripleHash
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>
            Entry data in &middot; composite digest out
          </div>
          <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 9, color: '#64748b', marginTop: 6 }}>
            reference: ~1.5&nbsp;µs / 100B payload
          </div>
        </div>
      </Html>
    </Float>
  )
}

/** Positions the fixed camera for a compact 3/4 elevated view of the hub
 * and its orbiting nodes — set once, since the camera never moves. */
function CameraRig() {
  const { camera } = useThree()
  useEffect(() => {
    camera.lookAt(0, 0, 0)
  }, [camera])
  return null
}

interface SceneProps {
  reducedMotion: boolean
}

function Scene({ reducedMotion }: SceneProps) {
  return (
    <>
      <CameraRig />
      <ambientLight intensity={0.25} />
      <pointLight position={[4, 4, 4]} intensity={0.4} color={HUB_COLOR} />
      <pointLight position={[-4, -2, -3]} intensity={0.2} color={CYAN} />

      <Hub reducedMotion={reducedMotion} />
      {ALGOS.map((algo) => (
        <AlgoNode key={algo.name} algo={algo} reducedMotion={reducedMotion} />
      ))}
      {ALGOS.map((algo) => (
        <ConvergencePulse key={algo.name} algo={algo} reducedMotion={reducedMotion} />
      ))}
    </>
  )
}

export interface TripleHashVisualProps {
  className?: string
}

/**
 * Self-contained 3D illustration of CITADEL's TripleHash mechanism, using the
 * same hub-and-orbit visual language as CitadelFortress/OrbitalRing: a
 * central hub (the entry data going in, and — on each periodic convergence
 * flash — the composite digest coming out) orbited by 3 nodes, one per hash
 * algorithm (SHA-256, SHA-512, BLAKE3), each pulsing independently and out of
 * phase to illustrate concurrent, independent processing. Periodically the
 * three send a pulse inward to the hub, which flashes and briefly shows an
 * illustrative composite-hash readout.
 *
 * The composite hash string and the "reference: ~1.5µs/100B" note are
 * illustrative placeholders, not a live computation — real benchmark figures
 * live in project docs. Drop this anywhere — it renders its own <Canvas> and
 * needs no props to be meaningful.
 */
export default function TripleHashVisual({ className }: TripleHashVisualProps) {
  const reducedMotion = usePrefersReducedMotion()

  return (
    <div className={className} style={{ width: '100%', height: '100%', minHeight: 240 }}>
      <Canvas
        camera={{ position: [3, 2.6, 4.2], fov: 42 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <Scene reducedMotion={reducedMotion} />
      </Canvas>
    </div>
  )
}
