import { useRef, useState, useCallback, useMemo, useEffect } from 'react'
import { useFrame } from '@react-three/fiber'
import { Float, Html, Sparkles } from '@react-three/drei'
import * as THREE from 'three'

/**
 * Runix Mobile — Giza pyramid split into 6 layers with gaps.
 * Same structure as Desktop but with mobile layers, plus MVNO orbital ring
 * around L3. Each sandbox cell is hoverable.
 */

interface LayerDef {
  name: string
  color: string
  services: string[]
  description: string
}

const LAYERS: LayerDef[] = [
  { name: 'Microkernel + HW',  color: '#ef4444', services: ['TrustZone', 'Enclave', 'TPM', 'Boot'],       description: 'Rust + ARM TrustZone root of trust.' },
  { name: 'Radio (RIL)',       color: '#f59e0b', services: ['Baseband', 'Modem', 'Antenna', 'Signal'],     description: 'Isolated user-space radio interface.' },
  { name: 'MVNO Stack',        color: '#10b981', services: ['SIM', 'eSIM', 'VoIP', 'Policy'],              description: 'Mobile network ops, CITADEL-gated.' },
  { name: 'CITADEL Layer',     color: '#3b82f6', services: ['MARSHAL', 'VIGIL', 'SIM-Gov', 'Roaming'],     description: 'SIM & roaming governance engine.' },
  { name: 'App Runtime',       color: '#7c3aed', services: ['WASM-A', 'WASM-B', 'WASM-C', 'Permit'],     description: 'WebAssembly MARSHAL-gated cells.' },
  { name: 'User Interface',    color: '#00f0ff', services: ['Dialer', 'Messages', 'Launcher', 'Settings'], description: 'Secure UI in sandboxed cells.' },
]

interface MVNONodeDef {
  label: string
  color: string
  description: string
  gate: string
}

const MVNO_NODES: MVNONodeDef[] = [
  { label: 'SIM',     color: '#00f0ff', description: 'SIM activation via MARSHAL Gate 1',  gate: 'G1' },
  { label: 'eSIM',    color: '#10b981', description: 'eSIM provisioning with audit trail',  gate: 'G1+G4' },
  { label: 'VoIP',    color: '#7c3aed', description: 'Encrypted + hashed voice trunk',      gate: 'All 5' },
  { label: 'Roaming', color: '#f59e0b', description: 'SoD-enforced roaming config',         gate: 'G1+G3' },
  { label: 'Policy',  color: '#3b82f6', description: 'Data policy with regulatory ref',     gate: 'G2+G4' },
]

const LAYER_HEIGHT = 0.3
const GAP = 0.2
const BASE_BOTTOM = 2.6
const TAPER = 0.3
const MVNO_LAYER = 2
const MVNO_RADIUS = 2.2
const MVNO_SPEED = 0.15

function getLayerY(i: number) { return i * (LAYER_HEIGHT + GAP) }
function getBottomSize(i: number) { return BASE_BOTTOM - i * TAPER }
function getTopSize(i: number) { return BASE_BOTTOM - (i + 1) * TAPER }

/** Mirrors the prefers-reduced-motion pattern used in MediaVideo.tsx for background video. */
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

function SandboxCell({ svc, x, z, size, color }: { svc: string; x: number; z: number; size: number; color: string }) {
  const [hovered, setHovered] = useState(false)
  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <group position={[x, 0.02, z]}>
      <mesh onPointerOver={onOver} onPointerOut={onOut}>
        <boxGeometry args={[size * 0.8, hovered ? 0.12 : 0.06, size * 0.8]} />
        <meshStandardMaterial
          color={color} emissive={color}
          emissiveIntensity={hovered ? 0.9 : 0.3}
          transparent opacity={hovered ? 0.8 : 0.4}
          toneMapped={false}
        />
      </mesh>
      <Html position={[0, 0.2, 0]} center distanceFactor={10} style={{
        pointerEvents: 'none',
        transition: 'opacity 0.15s ease, transform 0.15s ease',
        opacity: hovered ? 1 : 0,
        transform: hovered ? 'translateY(0)' : 'translateY(4px)',
      }}>
        <div style={{
          background: 'rgba(5,5,16,0.95)', border: `1px solid ${color}`,
          borderRadius: 7, padding: '4px 10px', whiteSpace: 'nowrap',
          fontFamily: 'JetBrains Mono, monospace', fontSize: 11,
          fontWeight: 600, color, boxShadow: `0 0 12px ${color}44`,
        }}>
          {svc}
        </div>
      </Html>
    </group>
  )
}

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
          key={svc} svc={svc}
          x={startX + (i % cols) * cellSize}
          z={startZ + Math.floor(i / cols) * cellSize}
          size={cellSize} color={color}
        />
      ))}
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
      <mesh geometry={geo} onPointerOver={onOver} onPointerOut={onOut}>
        <meshStandardMaterial
          wireframe color={layer.color} emissive={layer.color}
          emissiveIntensity={hovered ? 0.6 : 0.25}
          transparent opacity={hovered ? 0.8 : 0.5}
          toneMapped={false}
        />
      </mesh>
      <mesh geometry={geo}>
        <meshStandardMaterial
          color={layer.color} emissive={layer.color}
          emissiveIntensity={0.04} transparent opacity={0.06}
          side={THREE.DoubleSide}
        />
      </mesh>

      <SandboxGrid services={layer.services} size={topSize} y={LAYER_HEIGHT} color={layer.color} />

      <Html
        position={[bottomSize / 2 + 0.35, LAYER_HEIGHT / 2, 0]}
        center distanceFactor={10}
        style={{ pointerEvents: 'none', transition: 'opacity 0.2s', opacity: hovered ? 1 : 0.7 }}
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

      <Html
        position={[-(bottomSize / 2 + 0.35), LAYER_HEIGHT / 2, 0]}
        center distanceFactor={10}
        style={{ pointerEvents: 'none', transition: 'opacity 0.2s', opacity: hovered ? 1 : 0 }}
      >
        <div style={{
          background: 'rgba(5,5,16,0.95)', border: `1px solid ${layer.color}`,
          borderRadius: 8, padding: '6px 12px', whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif', fontSize: 11,
          color: '#94a3b8', boxShadow: `0 0 14px ${layer.color}33`,
        }}>
          {layer.description}
        </div>
      </Html>
    </group>
  )
}

/** MVNO orbital node with hover */
function MVNOOrbitalNode({ node, index }: { node: MVNONodeDef; index: number }) {
  const ref = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)
  const baseAngle = (index / MVNO_NODES.length) * Math.PI * 2
  const reducedMotion = usePrefersReducedMotion()

  useFrame(({ clock }) => {
    if (!ref.current) return
    if (!reducedMotion) {
      const t = clock.getElapsedTime() * MVNO_SPEED + baseAngle
      ref.current.position.x = Math.cos(t) * MVNO_RADIUS
      ref.current.position.z = Math.sin(t) * MVNO_RADIUS
    }
    const s = hovered ? 1.5 : 1
    ref.current.scale.lerp(new THREE.Vector3(s, s, s), 0.1)
  })

  const onOver = useCallback(() => { setHovered(true); document.body.style.cursor = 'pointer' }, [])
  const onOut = useCallback(() => { setHovered(false); document.body.style.cursor = 'auto' }, [])

  return (
    <mesh ref={ref} onPointerOver={onOver} onPointerOut={onOut}>
      <octahedronGeometry args={[0.13, 0]} />
      <meshStandardMaterial
        color={node.color} emissive={node.color}
        emissiveIntensity={hovered ? 1.2 : 0.5}
        toneMapped={false}
      />
      <Html center distanceFactor={8} style={{
        pointerEvents: 'none',
        transition: 'opacity 0.2s ease, transform 0.2s ease',
        opacity: hovered ? 1 : 0,
        transform: hovered ? 'translateY(0)' : 'translateY(6px)',
      }}>
        <div style={{
          background: 'rgba(5,5,16,0.95)', border: `1px solid ${node.color}`,
          borderRadius: 8, padding: '6px 12px', whiteSpace: 'nowrap',
          fontFamily: 'Inter, sans-serif', color: '#e2e8f0',
          boxShadow: `0 0 14px ${node.color}44`, transform: 'translateY(-18px)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}>
            <strong style={{ color: node.color, fontSize: 12 }}>{node.label}</strong>
            <span style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 3,
              background: `${node.color}15`, border: `1px solid ${node.color}25`,
              color: node.color, fontFamily: 'JetBrains Mono, monospace',
            }}>{node.gate}</span>
          </div>
          <div style={{ fontSize: 10, color: '#94a3b8' }}>{node.description}</div>
        </div>
      </Html>
    </mesh>
  )
}

/** Animated packet sphere that travels: MVNO node → L3 center → L4 center → L3 center → next node */
function MVNOFlowPacket() {
  const meshRef = useRef<THREE.Mesh>(null)
  const materialRef = useRef<THREE.MeshStandardMaterial>(null)
  const reducedMotion = usePrefersReducedMotion()
  const TRIP_DURATION = 2 // seconds per node trip
  const NODE_COUNT = MVNO_NODES.length
  const TOTAL_CYCLE = TRIP_DURATION * NODE_COUNT

  // Y positions relative to the MVNO group (which sits at mvnoY)
  const L3_REL_Y = 0    // L3 center is the same as mvnoY
  const L4_REL_Y = LAYER_HEIGHT + GAP // one layer up: getLayerY(3)+H/2 - mvnoY = 0.5

  // Colors for each phase
  const colorNode = new THREE.Color()
  const colorMarshal = new THREE.Color('#3b82f6')
  const colorExecute = new THREE.Color('#10b981')
  const tempColor = new THREE.Color()

  useFrame(({ clock }) => {
    if (!meshRef.current || !materialRef.current) return
    if (reducedMotion) return // freeze the packet in place
    const t = clock.getElapsedTime()

    // Which node trip are we on, and how far through it?
    const cycleT = t % TOTAL_CYCLE
    const nodeIndex = Math.floor(cycleT / TRIP_DURATION) % NODE_COUNT
    const nextIndex = (nodeIndex + 1) % NODE_COUNT
    const tripProgress = (cycleT % TRIP_DURATION) / TRIP_DURATION // 0..1

    // Compute current MVNO node position (they orbit)
    const baseAngleCur = (nodeIndex / NODE_COUNT) * Math.PI * 2
    const angleCur = t * MVNO_SPEED + baseAngleCur
    const nodeX = Math.cos(angleCur) * MVNO_RADIUS
    const nodeZ = Math.sin(angleCur) * MVNO_RADIUS

    // Compute next MVNO node position for the return leg
    const baseAngleNext = (nextIndex / NODE_COUNT) * Math.PI * 2
    const angleNext = t * MVNO_SPEED + baseAngleNext
    const nextX = Math.cos(angleNext) * MVNO_RADIUS
    const nextZ = Math.sin(angleNext) * MVNO_RADIUS

    // Waypoints: node → L3 center → L4 center → L3 center → next node
    // Phase 0: 0.00–0.25 node → L3 center
    // Phase 1: 0.25–0.50 L3 center → L4 center
    // Phase 2: 0.50–0.75 L4 center → L3 center
    // Phase 3: 0.75–1.00 L3 center → next node
    let px: number, py: number, pz: number

    if (tripProgress < 0.25) {
      const p = tripProgress / 0.25
      const ease = p * p * (3 - 2 * p) // smoothstep
      px = THREE.MathUtils.lerp(nodeX, 0, ease)
      py = THREE.MathUtils.lerp(L3_REL_Y, L3_REL_Y, ease)
      pz = THREE.MathUtils.lerp(nodeZ, 0, ease)
      // Color: from node color toward marshal
      colorNode.set(MVNO_NODES[nodeIndex].color)
      tempColor.copy(colorNode).lerp(colorMarshal, ease)
    } else if (tripProgress < 0.5) {
      const p = (tripProgress - 0.25) / 0.25
      const ease = p * p * (3 - 2 * p)
      px = 0
      py = THREE.MathUtils.lerp(L3_REL_Y, L4_REL_Y, ease)
      pz = 0
      // Color: marshal blue
      tempColor.copy(colorMarshal)
    } else if (tripProgress < 0.75) {
      const p = (tripProgress - 0.5) / 0.25
      const ease = p * p * (3 - 2 * p)
      px = 0
      py = THREE.MathUtils.lerp(L4_REL_Y, L3_REL_Y, ease)
      pz = 0
      // Color: marshal → execute green
      tempColor.copy(colorMarshal).lerp(colorExecute, ease)
    } else {
      const p = (tripProgress - 0.75) / 0.25
      const ease = p * p * (3 - 2 * p)
      px = THREE.MathUtils.lerp(0, nextX, ease)
      py = THREE.MathUtils.lerp(L3_REL_Y, L3_REL_Y, ease)
      pz = THREE.MathUtils.lerp(0, nextZ, ease)
      // Color: execute green → next node color
      colorNode.set(MVNO_NODES[nextIndex].color)
      tempColor.copy(colorExecute).lerp(colorNode, ease)
    }

    meshRef.current.position.set(px, py, pz)
    materialRef.current.color.copy(tempColor)
    materialRef.current.emissive.copy(tempColor)
  })

  return (
    <mesh ref={meshRef}>
      <sphereGeometry args={[0.06, 12, 12]} />
      <meshStandardMaterial
        ref={materialRef}
        color="#00f0ff"
        emissive="#00f0ff"
        emissiveIntensity={1.2}
        toneMapped={false}
        transparent
        opacity={0.9}
      />
    </mesh>
  )
}

export default function MobileDevice() {
  const phoneRef = useRef<THREE.Group>(null)
  const pyramidRef = useRef<THREE.Group>(null)
  const layersRef = useRef<THREE.Group>(null)
  const reducedMotion = usePrefersReducedMotion()

  useFrame(({ clock }) => {
    if (reducedMotion) return // freeze phone sway, pyramid spin, and layer bob
    const t = clock.getElapsedTime()
    if (phoneRef.current) {
      phoneRef.current.rotation.y = Math.sin(t * 0.15) * 0.3
    }
    if (pyramidRef.current) {
      pyramidRef.current.rotation.y = t * 0.12
    }
    if (layersRef.current) {
      layersRef.current.children.forEach((child, i) => {
        child.position.y = getLayerY(i) + Math.sin(t * 0.6 + i * 0.7) * 0.015
      })
    }
  })

  const totalH = LAYERS.length * LAYER_HEIGHT + (LAYERS.length - 1) * GAP
  const mvnoY = getLayerY(MVNO_LAYER) + LAYER_HEIGHT / 2
  const pyramidScale = 0.45

  return (
    <Float speed={0.5} rotationIntensity={0.04} floatIntensity={0.08}>
      <group ref={phoneRef}>

        {/* Phone body wireframe */}
        <mesh>
          <boxGeometry args={[2.2, 4.0, 0.15]} />
          <meshStandardMaterial
            wireframe
            color="#334155"
            emissive="#334155"
            emissiveIntensity={0.15}
            transparent
            opacity={0.35}
          />
        </mesh>

        {/* Screen glass */}
        <mesh position={[0, 0, 0.08]}>
          <planeGeometry args={[1.9, 3.6]} />
          <meshStandardMaterial
            color="#050510"
            emissive="#0a1628"
            emissiveIntensity={0.08}
            transparent
            opacity={0.5}
          />
        </mesh>

        {/* Notch */}
        <mesh position={[0, 1.7, 0.09]}>
          <boxGeometry args={[0.6, 0.1, 0.02]} />
          <meshBasicMaterial color="#1e293b" />
        </mesh>

        {/* Home indicator */}
        <mesh position={[0, -1.65, 0.09]}>
          <boxGeometry args={[0.5, 0.04, 0.01]} />
          <meshBasicMaterial color="#334155" transparent opacity={0.5} />
        </mesh>

        {/* Pyramid INSIDE the phone screen, scaled down */}
        <group ref={pyramidRef} position={[0, 0, 0.15]} scale={[pyramidScale, pyramidScale, pyramidScale]}>
          <group position={[0, -totalH / 2, 0]}>
            <group ref={layersRef}>
              {LAYERS.map((layer, i) => (
                <group key={layer.name} position={[0, getLayerY(i), 0]}>
                  <PyramidLayer layer={layer} index={i} />
                </group>
              ))}
            </group>

            {/* MVNO orbital ring around L3 */}
            <group position={[0, mvnoY, 0]}>
              <mesh rotation={[Math.PI / 2, 0, 0]}>
                <torusGeometry args={[MVNO_RADIUS, 0.015, 8, 64]} />
                <meshBasicMaterial color="#10b981" transparent opacity={0.25} />
              </mesh>
              {MVNO_NODES.map((node, i) => (
                <MVNOOrbitalNode key={node.label} node={node} index={i} />
              ))}
              <MVNOFlowPacket />
            </group>

            {/* Central axis */}
            <mesh position={[0, totalH / 2, 0]}>
              <cylinderGeometry args={[0.015, 0.015, totalH, 4]} />
              <meshBasicMaterial color="#10b981" transparent opacity={0.1} />
            </mesh>
          </group>

          <Sparkles count={30} scale={3} size={0.8} speed={0.15} color="#10b981" opacity={0.25} />
        </group>

        {/* Phone frame glow edges */}
        {[[-1.1, 0, 0], [1.1, 0, 0]].map((pos, i) => (
          <mesh key={i} position={pos as [number, number, number]}>
            <boxGeometry args={[0.02, 3.9, 0.14]} />
            <meshBasicMaterial color="#10b981" transparent opacity={0.06} />
          </mesh>
        ))}
      </group>
    </Float>
  )
}
