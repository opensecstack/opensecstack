import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Float, Html } from '@react-three/drei'
import * as THREE from 'three'
import { useHoverScale } from '../hooks/useHoverScale'
import { getOrbitPosition } from './orbitalMath'

/**
 * Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx /
 * MobileScene.tsx: continuous decorative animation is frozen (not just
 * slowed) when the user has requested reduced motion, while the hub and
 * ring of chained entries remain fully visible in a static arrangement.
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

const ENTRY_COUNT = 7
const RADIUS = 2.6
const ANCHOR_EVERY = 3 // stands in for "Ed25519 anchor every 100 entries"
const CYAN = '#00f0ff'
const VIOLET = '#7c3aed'
const ANCHOR_COLOR = '#e040fb'

// Illustrative/fake hashes only — purely decorative, not real audit data.
const FAKE_HASHES = [
  'a3f2c9…9c1e',
  'b71d40…22aa',
  '5e9f13…c04b',
  'ff2a88…7710',
  '0c4de6…b3f9',
  '91aa3c…e502',
  '2d7b5f…44c1',
]

interface EntryData {
  index: number
  angle: number
  isAnchor: boolean
  hash: string
}

function buildEntries(): EntryData[] {
  const step = (Math.PI * 2) / ENTRY_COUNT
  const entries: EntryData[] = []
  for (let i = 0; i < ENTRY_COUNT; i++) {
    entries.push({
      index: i,
      angle: step * i,
      isAnchor: (i + 1) % ANCHOR_EVERY === 0,
      hash: FAKE_HASHES[i % FAKE_HASHES.length],
    })
  }
  return entries
}

/** The WORM chain's root/genesis anchor — same visual language as CitadelFortress's hub. */
function ChainHub() {
  const ref = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  useFrame(() => {
    if (!ref.current) return
    ref.current.rotation.y += hovered ? 0.008 : 0.002
  })

  useHoverScale(ref, hovered, 1.15, 8)

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <Float speed={1.5} rotationIntensity={0.2} floatIntensity={0.3}>
      <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut}>
        <icosahedronGeometry args={[0.9, 1]} />
        <meshStandardMaterial
          wireframe
          color={VIOLET}
          emissive={VIOLET}
          emissiveIntensity={hovered ? 0.9 : 0.3}
          transparent
          opacity={hovered ? 1 : 0.85}
          toneMapped={false}
        />
      </mesh>

      <Html
        center
        distanceFactor={6}
        position={[0, 1.5, 0]}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.25s ease, transform 0.25s ease',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateY(0)' : 'translateY(8px)',
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: `1px solid ${VIOLET}`,
          borderRadius: 12,
          padding: '10px 16px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: `0 0 30px ${VIOLET}44`,
          textAlign: 'center',
        }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: VIOLET, letterSpacing: '0.08em' }}>
            WORM CHAIN
          </div>
          <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>
            Genesis anchor
          </div>
        </div>
      </Html>
    </Float>
  )
}

interface EntryNodeProps {
  entry: EntryData
  reducedMotion: boolean
}

/** An orbiting chain entry — same positioning/hover pattern as OrbitalNode. */
function EntryNode({ entry, reducedMotion }: EntryNodeProps) {
  const ref = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)
  const color = entry.isAnchor ? ANCHOR_COLOR : CYAN

  useFrame(({ clock }) => {
    if (!ref.current) return
    const elapsed = reducedMotion ? 0 : clock.getElapsedTime()
    const { x, y, z } = getOrbitPosition(elapsed, entry.angle, RADIUS)
    ref.current.position.set(x, y, z)
  })

  useHoverScale(ref, hovered, 1.4, 8)

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
      <sphereGeometry args={[0.22, 32, 32]} />
      <meshStandardMaterial
        color={color}
        emissive={color}
        emissiveIntensity={hovered ? 1.0 : entry.isAnchor ? 0.7 : 0.35}
        toneMapped={false}
      />

      {/* Hover tooltip — visual style matches OrbitalNode/CitadelFortress. */}
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
          border: `1px solid ${color}`,
          borderRadius: 10,
          padding: '8px 14px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          color: '#e2e8f0',
          boxShadow: `0 0 20px ${color}44`,
          textAlign: 'center',
          transform: 'translateY(-20px)',
        }}>
          <div style={{ fontSize: 12, fontWeight: 700, color }}>
            Entry #{1042 + entry.index}
          </div>
          <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>
            TripleHash: SHA-256 + SHA-512 + BLAKE3
          </div>
          <div style={{ fontSize: 10, color: '#5b6579', marginTop: 2, fontFamily: 'JetBrains Mono, monospace' }}>
            {entry.hash} <span style={{ color: '#3a4254' }}>(illustrative)</span>
          </div>
          {entry.index > 0 && (
            <div style={{ fontSize: 10, color: '#5b6579', marginTop: 2 }}>
              chained to entry #{1042 + entry.index - 1}
            </div>
          )}
          {entry.isAnchor && (
            <div style={{ fontSize: 10, color: ANCHOR_COLOR, marginTop: 4 }}>
              ⚓ Ed25519 anchor point
            </div>
          )}
        </div>
      </Html>
    </mesh>
  )
}

interface ChainLoopEdgesProps {
  entries: EntryData[]
  reducedMotion: boolean
}

/**
 * Thin dashed lines connecting each orbiting entry-node to the next one in
 * sequence (wrapping back to the first), so the ring reads as a closed
 * chain loop rather than independent satellites. Same line-drawing
 * technique as WormChainEdges.tsx, but node-to-node instead of node-to-hub.
 */
function ChainLoopEdges({ entries, reducedMotion }: ChainLoopEdgesProps) {
  const linesRef = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!linesRef.current) return
    const elapsed = reducedMotion ? 0 : clock.getElapsedTime()

    for (let i = 0; i < entries.length; i++) {
      const line = linesRef.current.children[i] as THREE.Line
      if (!line) continue

      const from = getOrbitPosition(elapsed, entries[i].angle, RADIUS)
      const next = entries[(i + 1) % entries.length]
      const to = getOrbitPosition(elapsed, next.angle, RADIUS)

      const positions = line.geometry.getAttribute('position')
      if (!positions) continue

      positions.setXYZ(0, from.x, from.y, from.z)
      positions.setXYZ(1, to.x, to.y, to.z)
      positions.needsUpdate = true
    }
  })

  return (
    <group ref={linesRef}>
      {entries.map((entry) => (
        <line key={entry.index}>
          <bufferGeometry>
            <bufferAttribute
              attach="attributes-position"
              count={2}
              array={new Float32Array([0, 0, 0, 0, 0, 0])}
              itemSize={3}
            />
          </bufferGeometry>
          <lineDashedMaterial
            color={VIOLET}
            transparent
            opacity={0.4}
            dashSize={0.2}
            gapSize={0.1}
          />
        </line>
      ))}
    </group>
  )
}

interface ChainPulseProps {
  entries: EntryData[]
  reducedMotion: boolean
}

/**
 * A small point of light that travels around the chain loop, following the
 * same orbit positions as the entry-nodes, to suggest each new entry being
 * cryptographically tied to the one before it.
 */
function ChainPulse({ entries, reducedMotion }: ChainPulseProps) {
  const pulseRef = useRef<THREE.Mesh>(null)
  const scratch = useMemo(() => new THREE.Vector3(), [])
  const count = entries.length

  useFrame(({ clock }) => {
    if (!pulseRef.current) return
    if (reducedMotion) {
      pulseRef.current.visible = false
      return
    }
    pulseRef.current.visible = true

    const elapsed = clock.getElapsedTime()
    const speed = 0.3 // loop-lengths per second
    const t = (elapsed * speed) % 1
    const posInLoop = count * t
    const i = Math.floor(posInLoop) % count
    const frac = posInLoop - Math.floor(posInLoop)
    const next = (i + 1) % count

    const a = getOrbitPosition(elapsed, entries[i].angle, RADIUS)
    const b = getOrbitPosition(elapsed, entries[next].angle, RADIUS)

    scratch.set(
      THREE.MathUtils.lerp(a.x, b.x, frac),
      THREE.MathUtils.lerp(a.y, b.y, frac),
      THREE.MathUtils.lerp(a.z, b.z, frac),
    )
    pulseRef.current.position.copy(scratch)
  })

  return (
    <mesh ref={pulseRef}>
      <sphereGeometry args={[0.08, 12, 12]} />
      <meshStandardMaterial color={CYAN} emissive={CYAN} emissiveIntensity={1.5} toneMapped={false} />
    </mesh>
  )
}

interface SceneProps {
  reducedMotion: boolean
}

function Scene({ reducedMotion }: SceneProps) {
  const entries = useMemo(() => buildEntries(), [])

  return (
    <>
      <ambientLight intensity={0.2} />
      <pointLight position={[5, 5, 5]} intensity={0.35} color={CYAN} />
      <pointLight position={[-5, -3, -4]} intensity={0.25} color={VIOLET} />

      <ChainHub />
      <ChainLoopEdges entries={entries} reducedMotion={reducedMotion} />
      {entries.map((entry) => (
        <EntryNode key={entry.index} entry={entry} reducedMotion={reducedMotion} />
      ))}
      <ChainPulse entries={entries} reducedMotion={reducedMotion} />
    </>
  )
}

export interface WormChainVisualProps {
  className?: string
}

/**
 * Self-contained 3D illustration of CITADEL's WORM audit chain, drawn in the
 * same hub-and-orbit visual language as the EcosystemScene's
 * CitadelFortress + OrbitalRing: a central genesis-anchor hub (icosahedron,
 * wireframe, emissive) with 7 orbiting entry-nodes positioned via the shared
 * `getOrbitPosition` helper, each linked to the next in sequence so the ring
 * reads as a closed chain loop. Every 3rd node stands in for the real
 * "Ed25519 anchor every 100 entries" mechanism, and a small light pulse
 * travels around the loop to suggest each entry being cryptographically
 * tied to the one before it.
 *
 * All hashes/entry numbers shown are illustrative placeholders, not real
 * audit data. Drop this anywhere — it renders its own <Canvas> and needs no
 * props to be meaningful.
 */
export default function WormChainVisual({ className }: WormChainVisualProps) {
  const reducedMotion = usePrefersReducedMotion()

  return (
    <div className={className} style={{ width: '100%', height: '100%', minHeight: 240 }}>
      <Canvas
        camera={{ position: [2.6, 3.2, 5.6], fov: 45 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <Scene reducedMotion={reducedMotion} />
      </Canvas>
    </div>
  )
}
