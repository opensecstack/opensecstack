import { useRef } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html, Sparkles } from '@react-three/drei'
import * as THREE from 'three'

/**
 * Giza Pyramid split into 6 layers with gaps between them.
 * Each layer is a truncated pyramid (frustum) with a glowing
 * grid on its top face representing sandboxed services.
 *
 * Layer 1 (Microkernel) is the base, Layer 6 (Application) is the apex.
 * The pyramid slowly rotates. Each layer's grid pulses independently.
 */

interface LayerDef {
  name: string
  color: string
  services: string[]
}

const LAYERS: LayerDef[] = [
  { name: 'Microkernel',       color: '#ef4444', services: ['IPC', 'Memory', 'Threads', 'Scheduler'] },
  { name: 'Capability Mgr',    color: '#f59e0b', services: ['Tokens', 'ACL', 'Signing', 'Revoke'] },
  { name: 'OS Services',       color: '#10b981', services: ['FS', 'Network', 'Audio', 'Display'] },
  { name: 'Grid Sandbox',      color: '#3b82f6', services: ['Cell-1', 'Cell-2', 'Cell-3', 'Permit'] },
  { name: 'CITADEL Runtime',   color: '#7c3aed', services: ['MARSHAL', 'WORM', 'VIGIL', 'AUGUR'] },
  { name: 'Application',       color: '#00f0ff', services: ['App-A', 'App-B', 'App-C', 'Shell'] },
]

const LAYER_HEIGHT = 0.35
const GAP = 0.18
const BASE_SIZE = 2.8       // bottom layer width
const TAPER = 0.32          // how much each layer narrows

/** Create a truncated pyramid (frustum) geometry */
function createFrustum(bottomSize: number, topSize: number, height: number): THREE.BufferGeometry {
  const b = bottomSize / 2
  const t = topSize / 2
  const h = height

  const vertices = new Float32Array([
    // Bottom face (y=0)
    -b, 0, -b,   b, 0, -b,   b, 0, b,   -b, 0, b,
    // Top face (y=h)
    -t, h, -t,   t, h, -t,   t, h, t,   -t, h, t,
  ])

  const indices = [
    // Bottom
    0, 2, 1,  0, 3, 2,
    // Top
    4, 5, 6,  4, 6, 7,
    // Front
    0, 1, 5,  0, 5, 4,
    // Back
    2, 3, 7,  2, 7, 6,
    // Left
    3, 0, 4,  3, 4, 7,
    // Right
    1, 2, 6,  1, 6, 5,
  ]

  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.BufferAttribute(vertices, 3))
  geo.setIndex(indices)
  geo.computeVertexNormals()
  return geo
}

/** Grid of small cubes on top of a layer representing sandboxed services */
function SandboxGrid({ services, size, y, color }: { services: string[]; size: number; y: number; color: string }) {
  const cols = 2
  const rows = Math.ceil(services.length / cols)
  const cellSize = (size * 0.7) / Math.max(cols, rows)
  const startX = -(cols - 1) * cellSize / 2
  const startZ = -(rows - 1) * cellSize / 2

  return (
    <group position={[0, y, 0]}>
      {services.map((svc, i) => {
        const col = i % cols
        const row = Math.floor(i / cols)
        const x = startX + col * cellSize
        const z = startZ + row * cellSize
        return (
          <group key={svc} position={[x, 0.02, z]}>
            <mesh>
              <boxGeometry args={[cellSize * 0.75, 0.06, cellSize * 0.75]} />
              <meshStandardMaterial
                color={color}
                emissive={color}
                emissiveIntensity={0.4}
                transparent
                opacity={0.5}
                toneMapped={false}
              />
            </mesh>
            <Html
              position={[0, 0.08, 0]}
              center
              distanceFactor={12}
              style={{ pointerEvents: 'none', whiteSpace: 'nowrap' }}
            >
              <span style={{
                fontSize: 7, fontFamily: 'JetBrains Mono, monospace',
                color, opacity: 0.8,
              }}>
                {svc}
              </span>
            </Html>
          </group>
        )
      })}

      {/* Grid lines on top face */}
      {Array.from({ length: cols + 1 }).map((_, ci) => {
        const x = startX - cellSize / 2 + ci * cellSize
        return (
          <mesh key={`v${ci}`} position={[x, 0.005, 0]}>
            <boxGeometry args={[0.005, 0.005, size * 0.75]} />
            <meshBasicMaterial color={color} transparent opacity={0.15} />
          </mesh>
        )
      })}
      {Array.from({ length: rows + 1 }).map((_, ri) => {
        const z = startZ - cellSize / 2 + ri * cellSize
        return (
          <mesh key={`h${ri}`} position={[0, 0.005, z]}>
            <boxGeometry args={[size * 0.75, 0.005, 0.005]} />
            <meshBasicMaterial color={color} transparent opacity={0.15} />
          </mesh>
        )
      })}
    </group>
  )
}

export default function DesktopKernel() {
  const groupRef = useRef<THREE.Group>(null)
  const frustumsRef = useRef<THREE.Group>(null)

  useFrame(({ clock }) => {
    if (!groupRef.current) return
    groupRef.current.rotation.y = clock.getElapsedTime() * 0.12

    // Gentle hover per layer
    if (frustumsRef.current) {
      const t = clock.getElapsedTime()
      frustumsRef.current.children.forEach((child, i) => {
        child.position.y = getLayerY(i) + Math.sin(t * 0.8 + i * 0.5) * 0.02
      })
    }
  })

  return (
    <Float speed={0.6} rotationIntensity={0.05} floatIntensity={0.1}>
      <group ref={groupRef} position={[0, -1.2, 0]}>
        <group ref={frustumsRef}>
          {LAYERS.map((layer, i) => {
            const bottomSize = BASE_SIZE - i * TAPER
            const topSize = BASE_SIZE - (i + 1) * TAPER
            const y = getLayerY(i)
            const geo = createFrustum(bottomSize, topSize, LAYER_HEIGHT)

            return (
              <group key={layer.name} position={[0, y, 0]}>
                {/* Frustum wireframe */}
                <mesh geometry={geo}>
                  <meshStandardMaterial
                    wireframe
                    color={layer.color}
                    emissive={layer.color}
                    emissiveIntensity={0.3}
                    transparent
                    opacity={0.6}
                    toneMapped={false}
                  />
                </mesh>

                {/* Solid faces - very subtle */}
                <mesh geometry={geo}>
                  <meshStandardMaterial
                    color={layer.color}
                    emissive={layer.color}
                    emissiveIntensity={0.05}
                    transparent
                    opacity={0.08}
                    side={THREE.DoubleSide}
                  />
                </mesh>

                {/* Sandbox grid on top of this layer */}
                <SandboxGrid
                  services={layer.services}
                  size={topSize}
                  y={LAYER_HEIGHT}
                  color={layer.color}
                />

                {/* Layer label */}
                <Html
                  position={[bottomSize / 2 + 0.3, LAYER_HEIGHT / 2, 0]}
                  center
                  distanceFactor={10}
                  style={{ pointerEvents: 'none', whiteSpace: 'nowrap' }}
                >
                  <div style={{
                    fontSize: 10, fontFamily: 'JetBrains Mono, monospace',
                    color: layer.color, opacity: 0.9,
                    textShadow: `0 0 8px ${layer.color}66`,
                    display: 'flex', alignItems: 'center', gap: 4,
                  }}>
                    <span style={{
                      background: `${layer.color}20`, border: `1px solid ${layer.color}40`,
                      borderRadius: 3, padding: '1px 4px', fontSize: 8, fontWeight: 700,
                    }}>
                      L{i + 1}
                    </span>
                    {layer.name}
                  </div>
                </Html>
              </group>
            )
          })}
        </group>

        {/* Vertical beam through the center of the pyramid */}
        <mesh position={[0, getTotalHeight() / 2, 0]}>
          <cylinderGeometry args={[0.015, 0.015, getTotalHeight(), 4]} />
          <meshBasicMaterial color="#00f0ff" transparent opacity={0.12} />
        </mesh>

        <Sparkles count={50} scale={5} size={1} speed={0.15} color="#00f0ff" opacity={0.25} />
      </group>
    </Float>
  )
}

function getLayerY(index: number): number {
  return index * (LAYER_HEIGHT + GAP)
}

function getTotalHeight(): number {
  return LAYERS.length * LAYER_HEIGHT + (LAYERS.length - 1) * GAP
}
