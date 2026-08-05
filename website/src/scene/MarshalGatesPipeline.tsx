import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import type { MutableRefObject } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'
import { marshalGates } from '../data/marshalGates'
import type { MarshalGate } from '../data/marshalGates'

interface MarshalGatesPipelineProps {
  className?: string
}

// ── Layout ──────────────────────────────────────────────────────────────
const NUM_GATES = marshalGates.length
const GATE_SPACING = 2.4
const GATE_XS: number[] = marshalGates.map((_, i) => (i - (NUM_GATES - 1) / 2) * GATE_SPACING)
const PATH_START = GATE_XS[0] - 2.2
const PATH_END = GATE_XS[GATE_XS.length - 1] + 2.2

// The real MARSHAL pipeline's 4th gate (AUGUR) is a behavioural-heuristics
// check that can reject an otherwise well-formed request. This codebase's
// marshalGates.ts names its 4th gate "Evidence" — same ordinal position in
// the 5-gate sequence — so that is where the illustrative REFUSE case stops.
const REFUSE_GATE_INDEX = 3
const REFUSE_CAP_PROGRESS = (GATE_XS[REFUSE_GATE_INDEX] - PATH_START) / (PATH_END - PATH_START)
const ARRIVAL_PROGRESS: number[] = GATE_XS.map((x) => (x - PATH_START) / (PATH_END - PATH_START))

// ── Timing ──────────────────────────────────────────────────────────────
const TRAVEL_DURATION = 4.2 // seconds for the packet to cross the whole pipeline
const HOLD_DURATION = 1.8 // seconds spent parked on the outcome before looping
const LOOP_DURATION = TRAVEL_DURATION + HOLD_DURATION
const ARRIVAL_TIMES: number[] = ARRIVAL_PROGRESS.map((p) => p * TRAVEL_DURATION)
const REFUSE_ARRIVAL_TIME = ARRIVAL_TIMES[REFUSE_GATE_INDEX]

// Roughly 1 in 4 loop iterations end in REFUSE — clearly the minority outcome.
const REFUSE_EVERY_N_CYCLES = 4

const FLASH_WINDOW = 0.6 // seconds a "pass" flash stays visibly hot
const FLASH_DECAY = 4.5 // exponential decay rate for the pass flash

// ── Colors (matching CitadelFortress / index.css accent palette) ────────
const COLOR_CYAN = '#00f0ff'
const COLOR_GREEN = '#10b981'
const COLOR_RED = '#ef4444'
const COLOR_VIOLET = '#7c3aed'

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
    camera.lookAt(0, 0.2, 0)
  }, [camera])
  return null
}

interface GateArchProps {
  gate: MarshalGate
  x: number
  index: number
  reducedMotion: boolean
  glowRef: (el: THREE.Mesh | null, index: number) => void
}

function GateArch({ gate, x, index, reducedMotion, glowRef }: GateArchProps) {
  const setGlowRef = useCallback((el: THREE.Mesh | null) => glowRef(el, index), [glowRef, index])

  // In reduced-motion mode the pipeline is static: the last gate (WORM-equivalent
  // "Schema") reads as the resting EXECUTE gate, everything else stays idle cyan.
  const staticColor = reducedMotion && index === NUM_GATES - 1 ? COLOR_GREEN : COLOR_CYAN

  return (
    <group position={[x, 0, 0]}>
      <mesh position={[-0.55, 1, 0]}>
        <boxGeometry args={[0.14, 2, 0.14]} />
        <meshStandardMaterial color={COLOR_VIOLET} emissive={COLOR_VIOLET} emissiveIntensity={0.4} toneMapped={false} />
      </mesh>
      <mesh position={[0.55, 1, 0]}>
        <boxGeometry args={[0.14, 2, 0.14]} />
        <meshStandardMaterial color={COLOR_VIOLET} emissive={COLOR_VIOLET} emissiveIntensity={0.4} toneMapped={false} />
      </mesh>
      <mesh position={[0, 2.07, 0]}>
        <boxGeometry args={[1.24, 0.14, 0.14]} />
        <meshStandardMaterial color={COLOR_VIOLET} emissive={COLOR_VIOLET} emissiveIntensity={0.4} toneMapped={false} />
      </mesh>

      {/* The reactive "energy plane" between the pillars — this is what flashes
          green/red as the packet passes or is refused. */}
      <mesh ref={setGlowRef} position={[0, 1, 0]}>
        <planeGeometry args={[0.9, 1.8]} />
        <meshStandardMaterial
          color={staticColor}
          emissive={staticColor}
          emissiveIntensity={reducedMotion ? 0.25 : 0.15}
          transparent
          opacity={0.22}
          side={THREE.DoubleSide}
          toneMapped={false}
        />
      </mesh>

      <Html center distanceFactor={9} position={[0, -0.55, 0]}>
        <div
          style={{
            background: 'rgba(5,5,16,0.95)',
            border: `1px solid ${COLOR_CYAN}`,
            borderRadius: 8,
            padding: '4px 10px',
            whiteSpace: 'nowrap',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 11,
            fontWeight: 600,
            letterSpacing: '0.05em',
            color: COLOR_CYAN,
            boxShadow: `0 0 14px ${COLOR_CYAN}33`,
            pointerEvents: 'none',
          }}
        >
          G{gate.number} &middot; {gate.name.toUpperCase()}
        </div>
      </Html>
    </group>
  )
}

interface OutcomeLabelProps {
  outcome: Outcome
  groupRef: MutableRefObject<THREE.Group | null>
}

function OutcomeLabel({ outcome, groupRef }: OutcomeLabelProps) {
  if (outcome === 'none') return null
  const isExecute = outcome === 'execute'
  const color = isExecute ? COLOR_GREEN : COLOR_RED
  return (
    <group ref={groupRef}>
      <Html center distanceFactor={9} position={[0, 2.9, 0]}>
        <div
          style={{
            background: 'rgba(5,5,16,0.95)',
            border: `1px solid ${color}`,
            borderRadius: 10,
            padding: '6px 14px',
            whiteSpace: 'nowrap',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 13,
            fontWeight: 700,
            letterSpacing: '0.08em',
            color,
            boxShadow: `0 0 20px ${color}55`,
            pointerEvents: 'none',
          }}
        >
          {isExecute ? 'EXECUTE' : 'REFUSE'}
        </div>
      </Html>
    </group>
  )
}

function AnimatedPipeline() {
  const packetRef = useRef<THREE.Mesh>(null)
  const packetMatRef = useRef<THREE.MeshStandardMaterial>(null)
  const glowRefs = useRef<(THREE.Mesh | null)[]>([])
  const outcomeGroupRef = useRef<THREE.Group>(null)
  const lastOutcomeRef = useRef<Outcome>('none')
  const [outcome, setOutcome] = useState<Outcome>('none')

  // Scratch colors, allocated once and reused every frame — never `new THREE.Color()` in useFrame.
  const cyan = useMemo(() => new THREE.Color(COLOR_CYAN), [])
  const green = useMemo(() => new THREE.Color(COLOR_GREEN), [])
  const red = useMemo(() => new THREE.Color(COLOR_RED), [])

  const setGlowRef = useCallback((el: THREE.Mesh | null, index: number) => {
    glowRefs.current[index] = el
  }, [])

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime()
    const cycleIndex = Math.floor(t / LOOP_DURATION)
    const cycleT = t - cycleIndex * LOOP_DURATION
    const willRefuse = cycleIndex % REFUSE_EVERY_N_CYCLES === REFUSE_EVERY_N_CYCLES - 1

    const rawProgress = Math.min(cycleT, TRAVEL_DURATION) / TRAVEL_DURATION
    const progress = willRefuse ? Math.min(rawProgress, REFUSE_CAP_PROGRESS) : rawProgress

    if (packetRef.current) {
      packetRef.current.position.x = THREE.MathUtils.lerp(PATH_START, PATH_END, progress)
    }
    if (packetMatRef.current) {
      const stopped = willRefuse && cycleT >= REFUSE_ARRIVAL_TIME
      packetMatRef.current.color.copy(stopped ? red : cyan)
      packetMatRef.current.emissive.copy(stopped ? red : cyan)
      packetMatRef.current.emissiveIntensity = stopped ? 0.9 : 0.7
    }

    for (let i = 0; i < GATE_XS.length; i++) {
      const mesh = glowRefs.current[i]
      if (!mesh) continue
      const mat = mesh.material as THREE.MeshStandardMaterial
      const arrivalTime = ARRIVAL_TIMES[i]
      const isRefuseGate = willRefuse && i === REFUSE_GATE_INDEX
      const gateIsUnreachable = willRefuse && i > REFUSE_GATE_INDEX

      if (gateIsUnreachable || cycleT < arrivalTime) {
        // Idle, not yet reached this cycle.
        mat.color.copy(cyan)
        mat.emissive.copy(cyan)
        mat.emissiveIntensity = 0.15
        mat.opacity = 0.22
        continue
      }

      if (isRefuseGate) {
        // Parked here for the rest of the cycle — a steady red hold, not a decaying flash.
        mat.color.copy(red)
        mat.emissive.copy(red)
        mat.emissiveIntensity = 0.85
        mat.opacity = 0.45
        continue
      }

      // Passed cleanly: a brief green flash that decays back to idle cyan.
      const sinceArrival = cycleT - arrivalTime
      if (sinceArrival < FLASH_WINDOW) {
        const decay = Math.exp(-FLASH_DECAY * sinceArrival)
        mat.color.copy(green)
        mat.emissive.copy(green)
        mat.emissiveIntensity = 0.3 + 0.9 * decay
        mat.opacity = 0.22 + 0.35 * decay
      } else {
        mat.color.copy(cyan)
        mat.emissive.copy(cyan)
        mat.emissiveIntensity = 0.15
        mat.opacity = 0.22
      }
    }

    // Outcome label: appears once the packet is parked at REFUSE, or once it
    // has crossed the full pipeline for EXECUTE.
    let desired: Outcome = 'none'
    if (willRefuse && cycleT >= REFUSE_ARRIVAL_TIME) {
      desired = 'refuse'
    } else if (!willRefuse && cycleT >= TRAVEL_DURATION) {
      desired = 'execute'
    }
    if (desired !== lastOutcomeRef.current) {
      lastOutcomeRef.current = desired
      setOutcome(desired)
    }
    if (outcomeGroupRef.current) {
      const targetX = willRefuse ? GATE_XS[REFUSE_GATE_INDEX] : PATH_END
      outcomeGroupRef.current.position.x = targetX
    }
  })

  return (
    <>
      {marshalGates.map((gate, i) => (
        <GateArch key={gate.number} gate={gate} x={GATE_XS[i]} index={i} reducedMotion={false} glowRef={setGlowRef} />
      ))}

      <mesh ref={packetRef} position={[PATH_START, 1, 0]}>
        <sphereGeometry args={[0.18, 24, 24]} />
        <meshStandardMaterial ref={packetMatRef} color={COLOR_CYAN} emissive={COLOR_CYAN} emissiveIntensity={0.7} toneMapped={false} />
      </mesh>

      <OutcomeLabel outcome={outcome} groupRef={outcomeGroupRef} />
    </>
  )
}

function StaticPipeline() {
  const setGlowRef = useCallback((_el: THREE.Mesh | null, _index: number) => {
    // No animation in reduced-motion mode — glow color is set once via GateArch's staticColor prop.
  }, [])
  const lastGateX = GATE_XS[GATE_XS.length - 1]

  return (
    <>
      {marshalGates.map((gate, i) => (
        <GateArch key={gate.number} gate={gate} x={GATE_XS[i]} index={i} reducedMotion glowRef={setGlowRef} />
      ))}

      {/* Static packet resting at the final gate with a static EXECUTE state. */}
      <mesh position={[lastGateX, 1, 0]}>
        <sphereGeometry args={[0.18, 24, 24]} />
        <meshStandardMaterial color={COLOR_GREEN} emissive={COLOR_GREEN} emissiveIntensity={0.8} toneMapped={false} />
      </mesh>

      <group position={[lastGateX, 0, 0]}>
        <Html center distanceFactor={9} position={[0, 2.9, 0]}>
          <div
            style={{
              background: 'rgba(5,5,16,0.95)',
              border: `1px solid ${COLOR_GREEN}`,
              borderRadius: 10,
              padding: '6px 14px',
              whiteSpace: 'nowrap',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: 13,
              fontWeight: 700,
              letterSpacing: '0.08em',
              color: COLOR_GREEN,
              boxShadow: `0 0 20px ${COLOR_GREEN}55`,
              pointerEvents: 'none',
            }}
          >
            EXECUTE
          </div>
        </Html>
      </group>
    </>
  )
}

/**
 * A self-contained, compact-panel-sized 3D visualization of MARSHAL's 5-gate
 * decision pipeline (see src/data/marshalGates.ts for the gate definitions).
 * An animated packet loops left-to-right through the gates: most iterations
 * reach a green EXECUTE outcome, but roughly 1 in 4 are stopped partway
 * through and flash red with a REFUSE outcome instead — an honest depiction
 * of MARSHAL actually rejecting requests rather than always succeeding.
 *
 * Respects prefers-reduced-motion: when set, the traveling-packet animation
 * is replaced by a single static packet parked at the final gate in a
 * static EXECUTE state, so the 5-gate structure stays legible without motion.
 */
export default function MarshalGatesPipeline({ className }: MarshalGatesPipelineProps) {
  const reducedMotion = useReducedMotion()

  return (
    <div className={className} style={{ width: '100%', height: '100%', minHeight: 260 }}>
      <Canvas camera={{ position: [0, 2.4, 10.5], fov: 42 }} dpr={[1, 1.5]} gl={{ antialias: true, alpha: true }}>
        <FixedCameraLookAt />

        <ambientLight intensity={0.15} />
        <pointLight position={[6, 6, 8]} intensity={0.3} color={COLOR_CYAN} />
        <pointLight position={[-6, -3, -6]} intensity={0.15} color={COLOR_VIOLET} />

        {reducedMotion ? <StaticPipeline /> : <AnimatedPipeline />}
      </Canvas>
    </div>
  )
}
