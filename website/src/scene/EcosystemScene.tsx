import { Suspense, useRef } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import CitadelFortress from './CitadelFortress'
import OrbitalRing from './OrbitalRing'
import WormChainEdges from './WormChainEdges'
import DataFlowPackets from './DataFlowPackets'
import ParticleGrid from './ParticleGrid'
import Effects from './postprocessing/Effects'
import { useScrollMax } from '../hooks/useScrollMax'
import VantaBackground from '../components/VantaBackground'

const START_POS = new THREE.Vector3(0, 2, 12)
const END_POS = new THREE.Vector3(0, 5, 16)
const START_LOOK = new THREE.Vector3(0, 0, 0)
const END_LOOK = new THREE.Vector3(0, -1, 0)
// Damping half-life-ish factor for THREE.MathUtils.damp — higher converges faster.
const DAMP_FACTOR = 4

/**
 * Reads window.scrollY each frame and smoothly damps the camera
 * position and lookAt target so the fortress recedes on scroll.
 */
function ScrollCamera() {
  const { camera } = useThree()
  const targetPos = useRef(START_POS.clone())
  const targetLook = useRef(START_LOOK.clone())
  const currentLook = useRef(START_LOOK.clone())

  // scrollHeight/innerHeight only change on resize/content changes — cache
  // them instead of reading layout-triggering DOM properties every frame.
  const scrollMax = useScrollMax()

  useFrame((_, delta) => {
    // Scroll progress: 0 at top, 1 when the page is fully scrolled
    const progress = Math.min(window.scrollY / scrollMax.current, 1)

    // Compute desired position and lookAt based on scroll
    targetPos.current.lerpVectors(START_POS, END_POS, progress)
    targetLook.current.lerpVectors(START_LOOK, END_LOOK, progress)

    // Delta-scaled damping so camera-follow speed is consistent regardless
    // of frame rate (a fixed-factor lerp would converge faster at higher fps).
    camera.position.x = THREE.MathUtils.damp(camera.position.x, targetPos.current.x, DAMP_FACTOR, delta)
    camera.position.y = THREE.MathUtils.damp(camera.position.y, targetPos.current.y, DAMP_FACTOR, delta)
    camera.position.z = THREE.MathUtils.damp(camera.position.z, targetPos.current.z, DAMP_FACTOR, delta)

    currentLook.current.x = THREE.MathUtils.damp(currentLook.current.x, targetLook.current.x, DAMP_FACTOR, delta)
    currentLook.current.y = THREE.MathUtils.damp(currentLook.current.y, targetLook.current.y, DAMP_FACTOR, delta)
    currentLook.current.z = THREE.MathUtils.damp(currentLook.current.z, targetLook.current.z, DAMP_FACTOR, delta)
    camera.lookAt(currentLook.current)
  })

  return null
}

export default function EcosystemScene() {
  return (
    <div className="scene-container">
      <VantaBackground />
      <Canvas
        camera={{ position: [0, 2, 12], fov: 55 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
        style={{ position: 'relative', zIndex: 1 }}
      >
        <ScrollCamera />

        <ambientLight intensity={0.15} />
        <pointLight position={[10, 10, 10]} intensity={0.3} color="#00f0ff" />
        <pointLight position={[-10, -5, -10]} intensity={0.15} color="#7c3aed" />

        <Suspense fallback={null}>
          <ParticleGrid />
          <CitadelFortress />
          <OrbitalRing />
          <WormChainEdges />
          <DataFlowPackets />
          <Effects />
        </Suspense>
      </Canvas>
    </div>
  )
}
