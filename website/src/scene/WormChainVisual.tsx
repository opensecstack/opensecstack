import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { Html } from '@react-three/drei'
import * as THREE from 'three'
import { useHoverScale } from '../hooks/useHoverScale'

/**
 * Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx /
 * MobileScene.tsx: continuous decorative animation is frozen (not just
 * slowed) when the user has requested reduced motion, while the static
 * chain itself remains fully visible.
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

const BLOCK_COUNT = 8
const SPACING = 1.9
const ANCHOR_EVERY = 4 // stands in for "Ed25519 anchor every 100 entries"
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
  'c68e01…9a7d',
]

interface BlockData {
  index: number
  position: [number, number, number]
  isAnchor: boolean
  hash: string
}

/**
 * A gentle curved layout so the chain reads as a single flowing sequence
 * rather than a rigid straight line.
 */
function layoutBlocks(): BlockData[] {
  const blocks: BlockData[] = []
  const total = BLOCK_COUNT
  const startX = -((total - 1) * SPACING) / 2
  for (let i = 0; i < total; i++) {
    const x = startX + i * SPACING
    // Shallow arc: peaks slightly in the middle.
    const t = i / (total - 1)
    const y = Math.sin(t * Math.PI) * 0.4
    const z = Math.cos(t * Math.PI) * -0.3
    blocks.push({
      index: i,
      position: [x, y, z],
      isAnchor: (i + 1) % ANCHOR_EVERY === 0,
      hash: FAKE_HASHES[i % FAKE_HASHES.length],
    })
  }
  return blocks
}

interface ChainBlockProps {
  block: BlockData
  reducedMotion: boolean
}

function ChainBlock({ block, reducedMotion }: ChainBlockProps) {
  const meshRef = useRef<THREE.Mesh>(null)
  const badgeRef = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)
  const color = block.isAnchor ? ANCHOR_COLOR : CYAN

  useHoverScale(meshRef, hovered, 1.25, 8)

  // Anchor badges get a slow, subtle pulse — frozen under reduced motion.
  useFrame(({ clock }) => {
    if (!badgeRef.current) return
    if (reducedMotion) {
      badgeRef.current.scale.setScalar(1)
      return
    }
    const pulse = 1 + Math.sin(clock.getElapsedTime() * 2.5 + block.index) * 0.15
    badgeRef.current.scale.setScalar(pulse)
  })

  const onOver = useCallback(() => {
    setHovered(true)
    document.body.style.cursor = 'pointer'
  }, [])
  const onOut = useCallback(() => {
    setHovered(false)
    document.body.style.cursor = 'auto'
  }, [])

  return (
    <group position={block.position}>
      <mesh ref={meshRef} onPointerOver={onOver} onPointerOut={onOut}>
        <boxGeometry args={[0.9, 0.55, 0.55]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={hovered ? 0.9 : block.isAnchor ? 0.5 : 0.3}
          transparent
          opacity={0.85}
          toneMapped={false}
        />
      </mesh>

      {block.isAnchor && (
        <mesh ref={badgeRef} position={[0, 0.55, 0]}>
          <octahedronGeometry args={[0.14, 0]} />
          <meshStandardMaterial
            color={ANCHOR_COLOR}
            emissive={ANCHOR_COLOR}
            emissiveIntensity={0.9}
            toneMapped={false}
          />
        </mesh>
      )}

      {/* Always-mounted abbreviated hash label, visibility via opacity. */}
      <Html
        center
        distanceFactor={7}
        position={[0, -0.55, 0]}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s ease',
          opacity: hovered ? 0 : 0.85,
        }}
      >
        <div
          style={{
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 10,
            color: block.isAnchor ? ANCHOR_COLOR : '#94a3b8',
            whiteSpace: 'nowrap',
          }}
        >
          {block.hash}
        </div>
      </Html>

      {/* Hover tooltip — visual style matches CitadelFortress/OrbitalNode. */}
      <Html
        center
        distanceFactor={7}
        position={[0, 1.05, 0]}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.25s ease, transform 0.25s ease',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateY(0)' : 'translateY(8px)',
        }}
      >
        <div
          style={{
            background: 'rgba(5,5,16,0.95)',
            border: `1px solid ${color}`,
            borderRadius: 10,
            padding: '8px 14px',
            whiteSpace: 'nowrap',
            fontFamily: 'Inter, sans-serif',
            color: '#e2e8f0',
            boxShadow: `0 0 20px ${color}44`,
            textAlign: 'center',
          }}
        >
          <div style={{ fontSize: 12, fontWeight: 700, color }}>
            Entry #{1042 + block.index}
          </div>
          <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>
            TripleHash: SHA-256 + SHA-512 + BLAKE3
          </div>
          <div style={{ fontSize: 10, color: '#5b6579', marginTop: 2, fontFamily: 'JetBrains Mono, monospace' }}>
            {block.hash}
          </div>
          {block.index > 0 && (
            <div style={{ fontSize: 10, color: '#5b6579', marginTop: 2 }}>
              ← chained to previous entry
            </div>
          )}
          {block.isAnchor && (
            <div style={{ fontSize: 10, color: ANCHOR_COLOR, marginTop: 4 }}>
              ⚓ Ed25519 anchor point
            </div>
          )}
        </div>
      </Html>
    </group>
  )
}

interface ChainLinksProps {
  blocks: BlockData[]
}

/** Thin cylinders connecting consecutive blocks — same visual language as WormChainEdges. */
function ChainLinks({ blocks }: ChainLinksProps) {
  const dir = useMemo(() => new THREE.Vector3(), [])
  const mid = useMemo(() => new THREE.Vector3(), [])
  const quat = useMemo(() => new THREE.Quaternion(), [])
  const up = useMemo(() => new THREE.Vector3(0, 1, 0), [])

  return (
    <>
      {blocks.slice(0, -1).map((block, i) => {
        const next = blocks[i + 1]
        const from = new THREE.Vector3(...block.position)
        const to = new THREE.Vector3(...next.position)
        dir.subVectors(to, from)
        const length = dir.length()
        mid.addVectors(from, to).multiplyScalar(0.5)
        quat.setFromUnitVectors(up, dir.clone().normalize())

        return (
          <mesh
            key={`link-${block.index}`}
            position={[mid.x, mid.y, mid.z]}
            quaternion={quat.clone()}
          >
            <cylinderGeometry args={[0.035, 0.035, length, 8]} />
            <meshStandardMaterial
              color={VIOLET}
              emissive={VIOLET}
              emissiveIntensity={0.4}
              transparent
              opacity={0.5}
              toneMapped={false}
            />
          </mesh>
        )
      })}
    </>
  )
}

interface ChainPulseProps {
  blocks: BlockData[]
  reducedMotion: boolean
}

/**
 * A small point of light that travels along the chain to suggest each new
 * entry being cryptographically tied to everything before it. Travels from
 * the newest block (last) back to the oldest (first).
 */
function ChainPulse({ blocks, reducedMotion }: ChainPulseProps) {
  const pulseRef = useRef<THREE.Mesh>(null)
  const scratch = useMemo(() => new THREE.Vector3(), [])
  const pathLength = blocks.length - 1

  useFrame(({ clock }) => {
    if (!pulseRef.current) return
    if (reducedMotion) {
      pulseRef.current.visible = false
      return
    }
    pulseRef.current.visible = true

    // Travels newest -> oldest, looping every few seconds.
    const speed = 0.35 // chain-lengths per second
    const t = (clock.getElapsedTime() * speed) % 1
    const posInChain = pathLength * (1 - t)
    const i = Math.min(Math.floor(posInChain), pathLength - 1)
    const frac = posInChain - i
    const a = blocks[i].position
    const b = blocks[Math.min(i + 1, blocks.length - 1)].position

    scratch.set(
      THREE.MathUtils.lerp(a[0], b[0], frac),
      THREE.MathUtils.lerp(a[1], b[1], frac),
      THREE.MathUtils.lerp(a[2], b[2], frac),
    )
    pulseRef.current.position.copy(scratch)
  })

  return (
    <mesh ref={pulseRef}>
      <sphereGeometry args={[0.09, 12, 12]} />
      <meshStandardMaterial color={CYAN} emissive={CYAN} emissiveIntensity={1.5} toneMapped={false} />
    </mesh>
  )
}

interface SceneProps {
  reducedMotion: boolean
}

function Scene({ reducedMotion }: SceneProps) {
  const blocks = useMemo(() => layoutBlocks(), [])

  return (
    <>
      <ambientLight intensity={0.2} />
      <pointLight position={[6, 6, 6]} intensity={0.35} color={CYAN} />
      <pointLight position={[-6, -3, -4]} intensity={0.2} color={VIOLET} />

      <ChainLinks blocks={blocks} />
      {blocks.map((block) => (
        <ChainBlock key={block.index} block={block} reducedMotion={reducedMotion} />
      ))}
      <ChainPulse blocks={blocks} reducedMotion={reducedMotion} />
    </>
  )
}

export interface WormChainVisualProps {
  className?: string
}

/**
 * Self-contained 3D illustration of CITADEL's WORM audit chain: a sequence
 * of hash-linked "entry" blocks, with every 4th block standing in for the
 * real "Ed25519 anchor every 100 entries" mechanism, and a small light pulse
 * traveling backward along the chain to suggest each entry being
 * cryptographically tied to everything before it.
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
        camera={{ position: [0, 2.4, 7], fov: 45 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <Scene reducedMotion={reducedMotion} />
      </Canvas>
    </div>
  )
}
