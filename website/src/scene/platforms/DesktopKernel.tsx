import { useRef, useState, useCallback, useMemo, useEffect } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html, Sparkles } from '@react-three/drei'
import * as THREE from 'three'

/**
 * Runix Desktop — Giza pyramid split into 6 layers with gaps.
 * Each layer is a truncated pyramid (frustum) with a grid of sandbox
 * cells on top. Hover on any cell shows its service name.
 * The whole structure rotates slowly. Orbital nodes orbit around it.
 */

interface LayerDef {
  name: string
  color: string
  services: string[]
  description: string
}

const LAYERS: LayerDef[] = [
  { name: 'Microkernel',       color: '#ef4444', services: ['IPC', 'Memory', 'Threads', 'Scheduler'],       description: 'Rust. ~50K LOC. Only privileged component.' },
  { name: 'Capability Manager', color: '#f59e0b', services: ['Tokens', 'ACL', 'Signing', 'Revoke'],         description: 'Capability-based access control.' },
  { name: 'OS Services',       color: '#10b981', services: ['FS', 'Network', 'Audio', 'Display'],           description: 'All run as isolated user-space.' },
  { name: 'Grid Sandbox',      color: '#3b82f6', services: ['WASM-1', 'WASM-2', 'WASM-3', 'Permit'],       description: 'WebAssembly cell isolation.' },
  { name: 'CITADEL Runtime',   color: '#7c3aed', services: ['MARSHAL', 'WORM', 'VIGIL', 'AUGUR'],           description: 'Governance as infrastructure.' },
  { name: 'Application Layer', color: '#00f0ff', services: ['App-A', 'App-B', 'App-C', 'Shell'],            description: 'WASM apps. Zero-trust sandbox.' },
]

const LAYER_HEIGHT = 0.3
const GAP = 0.2
const BASE_BOTTOM = 2.6
const TAPER = 0.3

function getLayerY(i: number) { return i * (LAYER_HEIGHT + GAP) }
function getBottomSize(i: number) { return BASE_BOTTOM - i * TAPER }
function getTopSize(i: number) { return BASE_BOTTOM - (i + 1) * TAPER }

function createFrustum(bottom: number, top: number, h: number): THREE.BufferGeometry {
  const b = bottom / 2, t = top / 2
  const verts = new Float32Array([
    -b,0,-b, b,0,-b, b,0,b, -b,0,b,
    -t,h,-t, t,h,-t, t,h,t, -t,h,t,
  ])
  const idx = [0,2,1,0,3,2, 4,5,6,4,6,7, 0,1,5,0,5,4, 2,3,7,2,7,6, 3,0,4,3,4,7, 1,2,6,1,6,5]
  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.BufferAttribute(verts, 3))
  geo.setIndex(idx)
  geo.computeVertexNormals()
  return geo
}

/** Single hoverable sandbox cell cube */
function SandboxCell({ svc, x, z, size, color }: { svc: string; x: number; z: number; size: number; color: string }) {
  const [hovered, setHovered] = useState(false)
  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <group position={[x, 0.02, z]}>
      <mesh onPointerOver={onOver} onPointerOut={onOut}>
        <boxGeometry args={[size * 0.8, hovered ? 0.12 : 0.06, size * 0.8]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={hovered ? 0.9 : 0.3}
          transparent
          opacity={hovered ? 0.8 : 0.4}
          toneMapped={false}
        />
      </mesh>
      <Html
        position={[0, 0.2, 0]}
        center
        distanceFactor={10}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.15s ease, transform 0.15s ease',
          opacity: hovered ? 1 : 0,
          transform: hovered ? 'translateY(0)' : 'translateY(4px)',
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: `1px solid ${color}`,
          borderRadius: 7,
          padding: '4px 10px',
          whiteSpace: 'nowrap',
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: 11,
          fontWeight: 600,
          color,
          boxShadow: `0 0 12px ${color}44`,
        }}>
          {svc}
        </div>
      </Html>
    </group>
  )
}

/** Grid of sandbox cells on top of a layer */
function SandboxGrid({ services, size, y, color }: { services: string[]; size: number; y: number; color: string }) {
  const cols = 2
  const rows = Math.ceil(services.length / cols)
  const cellSize = (size * 0.7) / Math.max(cols, rows)
  const startX = -(cols - 1) * cellSize / 2
  const startZ = -(rows - 1) * cellSize / 2

  return (
    <group position={[0, y, 0]}>
      {services.map((svc, i) => (
        <SandboxCell
          key={svc}
          svc={svc}
          x={startX + (i % cols) * cellSize}
          z={startZ + Math.floor(i / cols) * cellSize}
          size={cellSize}
          color={color}
        />
      ))}
      {/* Grid lines */}
      {Array.from({ length: cols + 1 }).map((_, ci) => (
        <mesh key={`v${ci}`} position={[startX - cellSize / 2 + ci * cellSize, 0.003, 0]}>
          <boxGeometry args={[0.005, 0.005, size * 0.75]} />
          <meshBasicMaterial color={color} transparent opacity={0.12} />
        </mesh>
      ))}
      {Array.from({ length: rows + 1 }).map((_, ri) => (
        <mesh key={`h${ri}`} position={[0, 0.003, startZ - cellSize / 2 + ri * cellSize]}>
          <boxGeometry args={[size * 0.75, 0.005, 0.005]} />
          <meshBasicMaterial color={color} transparent opacity={0.12} />
        </mesh>
      ))}
    </group>
  )
}

/** Single pyramid layer — frustum + hover label + sandbox grid */
function PyramidLayer({ layer, index }: { layer: LayerDef; index: number }) {
  const [hovered, setHovered] = useState(false)
  const bottomSize = getBottomSize(index)
  const topSize = getTopSize(index)
  // Memoized so hover toggles (onPointerOver/onPointerOut) don't rebuild the
  // BufferGeometry every re-render — only recomputed when the layer's
  // dimensions actually change.
  const geo = useMemo(
    () => createFrustum(bottomSize, topSize, LAYER_HEIGHT),
    [bottomSize, topSize],
  )

  // Dispose the GPU buffers when the geometry is replaced or the layer unmounts.
  useEffect(() => {
    return () => geo.dispose()
  }, [geo])

  const onOver = useCallback(() => setHovered(true), [])
  const onOut = useCallback(() => setHovered(false), [])

  return (
    <group>
      {/* Wireframe frustum */}
      <mesh geometry={geo} onPointerOver={onOver} onPointerOut={onOut}>
        <meshStandardMaterial
          wireframe
          color={layer.color}
          emissive={layer.color}
          emissiveIntensity={hovered ? 0.6 : 0.25}
          transparent
          opacity={hovered ? 0.8 : 0.5}
          toneMapped={false}
        />
      </mesh>
      {/* Solid inner fill */}
      <mesh geometry={geo}>
        <meshStandardMaterial
          color={layer.color}
          emissive={layer.color}
          emissiveIntensity={0.04}
          transparent
          opacity={0.06}
          side={THREE.DoubleSide}
        />
      </mesh>

      {/* Sandbox grid on top */}
      <SandboxGrid services={layer.services} size={topSize} y={LAYER_HEIGHT} color={layer.color} />

      {/* Layer label on the side */}
      <Html
        position={[bottomSize / 2 + 0.35, LAYER_HEIGHT / 2, 0]}
        center
        distanceFactor={10}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s',
          opacity: hovered ? 1 : 0.7,
        }}
      >
        <div style={{
          display: 'flex', alignItems: 'center', gap: 5,
          fontFamily: 'JetBrains Mono, monospace', fontSize: 10,
          color: layer.color, whiteSpace: 'nowrap',
          textShadow: `0 0 8px ${layer.color}66`,
        }}>
          <span style={{
            background: `${layer.color}20`, border: `1px solid ${layer.color}40`,
            borderRadius: 3, padding: '1px 5px', fontSize: 9, fontWeight: 700,
          }}>L{index + 1}</span>
          {layer.name}
        </div>
      </Html>

      {/* Hover description popup */}
      <Html
        position={[-(bottomSize / 2 + 0.35), LAYER_HEIGHT / 2, 0]}
        center
        distanceFactor={10}
        style={{
          pointerEvents: 'none',
          transition: 'opacity 0.2s ease',
          opacity: hovered ? 1 : 0,
        }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)',
          border: `1px solid ${layer.color}`,
          borderRadius: 8,
          padding: '6px 12px',
          whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif',
          fontSize: 11,
          color: '#94a3b8',
          boxShadow: `0 0 14px ${layer.color}33`,
        }}>
          {layer.description}
        </div>
      </Html>
    </group>
  )
}

export default function DesktopKernel() {
  const groupRef = useRef<THREE.Group>(null)
  const layersRef = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    const t = clock.getElapsedTime()
    if (groupRef.current) groupRef.current.rotation.y = t * 0.1
    if (layersRef.current) {
      layersRef.current.children.forEach((child, i) => {
        child.position.y = getLayerY(i) + Math.sin(t * 0.6 + i * 0.7) * 0.025
      })
    }
  })

  const totalH = LAYERS.length * LAYER_HEIGHT + (LAYERS.length - 1) * GAP

  return (
    <Float speed={0.5} rotationIntensity={0.04} floatIntensity={0.08}>
      <group ref={groupRef} position={[0, -totalH / 2, 0]}>
        <group ref={layersRef}>
          {LAYERS.map((layer, i) => (
            <group key={layer.name} position={[0, getLayerY(i), 0]}>
              <PyramidLayer layer={layer} index={i} />
            </group>
          ))}
        </group>

        {/* Central axis beam */}
        <mesh position={[0, totalH / 2, 0]}>
          <cylinderGeometry args={[0.012, 0.012, totalH, 4]} />
          <meshBasicMaterial color="#ef4444" transparent opacity={0.08} />
        </mesh>

        <Sparkles count={40} scale={4} size={1} speed={0.15} color="#ef4444" opacity={0.2} />
      </group>
    </Float>
  )
}
