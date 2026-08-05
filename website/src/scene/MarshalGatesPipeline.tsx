import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Float, Html } from '@react-three/drei'
import * as THREE from 'three'
import { marshalGates } from '../data/marshalGates'
import type { MarshalGate } from '../data/marshalGates'
import { useHoverScale } from '../hooks/useHoverScale'
import { getOrbitPosition } from './orbitalMath'

interface MarshalGatesPipelineProps {
  className?: string
}

// ── Layout ──────────────────────────────────────────────────────────────
const GATE_COUNT = marshalGates.length
const ORBIT_RADIUS = 2.6

// ── Timing ──────────────────────────────────────────────────────────────
// Each gate lights up in turn, one every STEP_DURATION seconds, then the
// hub holds its outcome glow for HOLD_DURATION before the loop restarts.
const STEP_DURATION = 0.85
const SEQUENCE_DURATION = GATE_COUNT * STEP_DURATION
const HOLD_DURATION = 1.8
const LOOP_DURATION = SEQUENCE_DURATION + HOLD_DURATION
const ARRIVAL_TIMES: number[] = marshalGates.map((_, i) => i * STEP_DURATION)

// The real MARSHAL pipeline's 4th gate is a behavioural/evidence check that
// can reject an otherwise well-formed request — same ordinal position this
// codebase's marshalGates.ts calls "Evidence" — so that is where the
// illustrative REFUSE case stops.
const REFUSE_GATE_INDEX = 3
const REFUSE_ARRIVAL_TIME = ARRIVAL_TIMES[REFUSE_GATE_INDEX]

// Roughly 1 in 4 loop iterations end in REFUSE — clearly the minority outcome.
const REFUSE_EVERY_N_CYCLES = 4

const FLASH_WINDOW = 0.6 // seconds a "pass" flash stays visibly hot
const FLASH_DECAY = 4.5 // exponential decay rate for the pass flash

// ── Colors (matching CitadelFortress / OrbitalNode accent palette) ──────
const COLOR_CYAN = '#00f0ff'
const COLOR_VIOLET = '#7c3aed'
const COLOR_GREEN = '#10b981'
const COLOR_RED = '#ef4444'

type Outcome = 'none' | 'execute' | 'refuse'

function useReducedMotion(): boolean {
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

/** Sets the camera's initial orientation once — this scene uses a fixed camera, no orbit controls. */
function FixedCameraLookAt() {
  const { camera } = useThree()
  useEffect(() => {
    camera.lookAt(0, 0, 0)
  }, [camera])
  return null
}

/**
 * The MARSHAL evaluation core — visually consistent with CitadelFortress's
 * hub (wireframe icosahedron + emissive glow + gentle Float idle motion),
 * using a violet accent to read as a distinct-but-related engine.
 */
interface HubProps {
  reducedMotion: boolean
}

function MarshalHub({ reducedMotion }: HubProps) {
  const meshRef = useRef<THREE.Mesh>(null)
  const matRef = useRef<THREE.MeshStandardMaterial>(null)
  const lastOutcomeRef = useRef<Outcome>('none')
  const [outcome, setOutcome] = useState<Outcome>(reducedMotion ? 'execute' : 'none')

  // Scratch colors, allocated once and reused every frame.
  const violet = useMemo(() => new THREE.Color(COLOR_VIOLET), [])
  const green = useMemo(() => new THREE.Color(COLOR_GREEN), [])
  const red = useMemo(() => new THREE.Color(COLOR_RED), [])

  useFrame(({ clock }, delta) => {
    if (meshRef.current) {
      meshRef.current.rotation.y += delta * 0.15
    }
    if (reducedMotion) return

    const t = clock.getElapsedTime()
    const cycleIndex = Math.floor(t / LOOP_DURATION)
    const cycleT = t - cycleIndex * LOOP_DURATION
    const willRefuse = cycleIndex % REFUSE_EVERY_N_CYCLES === REFUSE_EVERY_N_CYCLES - 1

    let desired: Outcome = 'none'
    if (willRefuse && cycleT >= REFUSE_ARRIVAL_TIME) {
      desired = 'refuse'
    } else if (!willRefuse && cycleT >= SEQUENCE_DURATION) {
      desired = 'execute'
    }
    if (desired !== lastOutcomeRef.current) {
      lastOutcomeRef.current = desired
      setOutcome(desired)
    }

    const mat = matRef.current
    if (mat) {
      if (desired === 'execute') {
        mat.color.copy(green)
        mat.emissive.copy(green)
        mat.emissiveIntensity = 0.9
      } else if (desired === 'refuse') {
        mat.color.copy(red)
        mat.emissive.copy(red)
        mat.emissiveIntensity = 0.9
      } else {
        mat.color.copy(violet)
        mat.emissive.copy(violet)
        mat.emissiveIntensity = 0.35
      }
    }
  })

  const labelColor = outcome === 'execute' ? COLOR_GREEN : outcome === 'refuse' ? COLOR_RED : null

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={meshRef}>
        <icosahedronGeometry args={[1, 1]} />
        <meshStandardMaterial
          ref={matRef}
          wireframe
          color={reducedMotion ? COLOR_GREEN : COLOR_VIOLET}
          emissive={reducedMotion ? COLOR_GREEN : COLOR_VIOLET}
          emissiveIntensity={reducedMotion ? 0.9 : 0.35}
          transparent
          opacity={0.9}
          toneMapped={false}
        />
      </mesh>

      {labelColor && (
        <Html center distanceFactor={8} position={[0, 1.8, 0]}>
          <div
            style={{
              background: 'rgba(5,5,16,0.95)',
              border: `1px solid ${labelColor}`,
              borderRadius: 10,
              padding: '6px 14px',
              whiteSpace: 'nowrap',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 13,
              fontWeight: 700,
              letterSpacing: '0.08em',
              color: labelColor,
              boxShadow: `0 0 20px ${labelColor}55`,
              pointerEvents: 'none',
            }}
          >
            {outcome === 'execute' ? 'EXECUTE' : 'REFUSE'}
          </div>
        </Html>
      )}
    </Float>
  )
}

interface GateNodeProps {
  gate: MarshalGate
  index: number
  angle: number
  reducedMotion: boolean
}

/**
 * One orbiting gate node — mirrors OrbitalNode's sphere + getOrbitPosition +
 * useHoverScale + fade-in Html tooltip pattern. Its emissive material also
 * brightens on its own, in turn, as the automatic gate sequence reaches it —
 * the same emissiveIntensity technique OrbitalNode uses for hover, just
 * driven by a timer instead of a pointer.
 */
function GateNode({ gate, index, angle, reducedMotion }: GateNodeProps) {
  const meshRef = useRef<THREE.Mesh>(null)
  const matRef = useRef<THREE.MeshStandardMaterial>(null)
  const [hovered, setHovered] = useState(false)

  const cyan = useMemo(() => new THREE.Color(COLOR_CYAN), [])
  const green = useMemo(() => new THREE.Color(COLOR_GREEN), [])
  const red = useMemo(() => new THREE.Color(COLOR_RED), [])

  const restPosition = useMemo(() => getOrbitPosition(0, angle, ORBIT_RADIUS), [angle])

  useFrame(({ clock }) => {
    const mesh = meshRef.current
    const mat = matRef.current
    if (!mesh || !mat) return

    if (reducedMotion) {
      mesh.position.set(restPosition.x, restPosition.y, restPosition.z)
      mat.color.copy(green)
      mat.emissive.copy(green)
      mat.emissiveIntensity = hovered ? 1.0 : 0.5
      return
    }

    const { x, y, z } = getOrbitPosition(clock.getElapsedTime(), angle, ORBIT_RADIUS)
    mesh.position.set(x, y, z)

    const t = clock.getElapsedTime()
    const cycleIndex = Math.floor(t / LOOP_DURATION)
    const cycleT = t - cycleIndex * LOOP_DURATION
    const willRefuse = cycleIndex % REFUSE_EVERY_N_CYCLES === REFUSE_EVERY_N_CYCLES - 1
    const arrivalTime = ARRIVAL_TIMES[index]
    const isRefuseGate = willRefuse && index === REFUSE_GATE_INDEX
    const isUnreachable = willRefuse && index > REFUSE_GATE_INDEX

    let color = cyan
    let intensity = 0.2

    if (isUnreachable || cycleT < arrivalTime) {
      color = cyan
      intensity = 0.2
    } else if (isRefuseGate) {
      // Parked here for the rest of the cycle — a steady red hold.
      color = red
      intensity = 0.9
    } else {
      const sinceArrival = cycleT - arrivalTime
      if (sinceArrival < FLASH_WINDOW) {
        const decay = Math.exp(-FLASH_DECAY * sinceArrival)
        color = green
        intensity = 0.35 + 0.9 * decay
      } else {
        color = green
        intensity = 0.35
      }
    }

    mat.color.copy(color)
    mat.emissive.copy(color)
    mat.emissiveIntensity = hovered ? 1.0 : intensity
  })

  // Delta-scaled damping so the hover-scale animation converges in
  // consistent wall-clock time regardless of display refresh rate.
  useHoverScale(meshRef, hovered, 1.4, 8)

  const onOver = useCallback(() => {
    setHovered(true)
    document.body.style.cursor = 'pointer'
  }, [])
  const onOut = useCallback(() => {
    setHovered(false)
    document.body.style.cursor = 'auto'
  }, [])

  return (
    <mesh
      ref={meshRef}
      position={[restPosition.x, restPosition.y, restPosition.z]}
      onPointerOver={onOver}
      onPointerOut={onOut}
    >
      <sphereGeometry args={[0.28, 32, 32]} />
      <meshStandardMaterial ref={matRef} color={COLOR_CYAN} emissive={COLOR_CYAN} emissiveIntensity={0.2} toneMapped={false} />

      <Html
        center
        distanceFactor={8}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s ease',
          opacity: hovered ? 1 : 0,
        }}
      >
        <div
          style={{
            background: 'rgba(5,5,16,0.95)',
            border: `1px solid ${COLOR_CYAN}`,
            borderRadius: 10,
            padding: '8px 14px',
            whiteSpace: 'nowrap',
            fontFamily: 'Inter, sans-serif',
            color: '#e2e8f0',
            boxShadow: `0 0 20px ${COLOR_CYAN}44`,
            transform: 'translateY(-20px)',
            maxWidth: 220,
            textAlign: 'left',
          }}
        >
          <div
            style={{
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: '0.05em',
              color: COLOR_CYAN,
            }}
          >
            G{gate.number} &middot; {gate.name.toUpperCase()}
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 4, whiteSpace: 'normal' }}>
            {gate.description}
          </div>
        </div>
      </Html>
    </mesh>
  )
}

function HubAndGates({ reducedMotion }: { reducedMotion: boolean }) {
  const step = (Math.PI * 2) / GATE_COUNT

  return (
    <group>
      <MarshalHub reducedMotion={reducedMotion} />
      {marshalGates.map((gate, i) => (
        <GateNode key={gate.number} gate={gate} index={i} angle={step * i} reducedMotion={reducedMotion} />
      ))}
    </group>
  )
}

/**
 * A self-contained, compact-panel-sized 3D visualization of MARSHAL's 5-gate
 * decision engine (see src/data/marshalGates.ts for the gate definitions),
 * built in the same hub-and-orbit visual language as CitadelFortress +
 * OrbitalNode/OrbitalRing: a central icosahedron core with the five gates
 * orbiting it like moons.
 *
 * An automatic "signal" sweeps around the ring in gate order — each node's
 * own emissive material briefly pulses green as the sequence reaches it,
 * mirroring OrbitalNode's hover-brighten technique but timer-driven. Most
 * loops (~3 in 4) complete the full ring and flash the hub green with an
 * EXECUTE label; roughly 1 in 4 stop partway at the "Evidence" gate (the
 * behavioural-check position) and flash both that node and the hub red with
 * a REFUSE label instead — an honest depiction of MARSHAL actually
 * rejecting requests rather than always succeeding.
 *
 * Respects prefers-reduced-motion: when set, the orbit and sequence freeze
 * — all five nodes sit at their rest positions in a static green state and
 * the hub shows a static green EXECUTE glow, with no continuous rotation or
 * pulsing.
 */
export default function MarshalGatesPipeline({ className }: MarshalGatesPipelineProps) {
  const reducedMotion = useReducedMotion()

  return (
    <div className={className} style={{ width: '100%', height: '100%', minHeight: 260 }}>
      <Canvas camera={{ position: [3, 3.2, 6.4], fov: 45 }} dpr={[1, 1.5]} gl={{ antialias: true, alpha: true }}>
        <FixedCameraLookAt />

        <ambientLight intensity={0.15} />
        <pointLight position={[5, 5, 6]} intensity={0.35} color={COLOR_VIOLET} />
        <pointLight position={[-5, -2, -5]} intensity={0.15} color={COLOR_CYAN} />

        <HubAndGates reducedMotion={reducedMotion} />
      </Canvas>
    </div>
  )
}
