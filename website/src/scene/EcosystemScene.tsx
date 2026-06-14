import { Suspense, useRef } from 'react'
import { Canvas, useFrame, useThree } from '@react-three/fiber'
import * as THREE from 'three'
import CitadelFortress from './CitadelFortress'
import OrbitalRing from './OrbitalRing'
import WormChainEdges from './WormChainEdges'
import DataFlowPackets from './DataFlowPackets'
import ParticleGrid from './ParticleGrid'
import Effects from './postprocessing/Effects'

const START_POS = new THREE.Vector3(0, 2, 12)
const END_POS = new THREE.Vector3(0, 5, 16)
const START_LOOK = new THREE.Vector3(0, 0, 0)
const END_LOOK = new THREE.Vector3(0, -1, 0)
const LERP_FACTOR = 0.03

/**
 * Reads window.scrollY each frame and smoothly lerps the camera
 * position and lookAt target so the fortress recedes on scroll.
 */
function ScrollCamera() {
  const { camera } = useThree()
  const targetPos = useRef(START_POS.clone())
  const targetLook = useRef(START_LOOK.clone())
  const currentLook = useRef(START_LOOK.clone())

  useFrame(() => {
    // Scroll progress: 0 at top, 1 when the page is fully scrolled
    const scrollMax = Math.max(
      1,
      document.documentElement.scrollHeight - window.innerHeight,
    )
    const progress = Math.min(window.scrollY / scrollMax, 1)

    // Compute desired position and lookAt based on scroll
    targetPos.current.lerpVectors(START_POS, END_POS, progress)
    targetLook.current.lerpVectors(START_LOOK, END_LOOK, progress)

    // Smoothly lerp camera toward targets
    camera.position.lerp(targetPos.current, LERP_FACTOR)
    currentLook.current.lerp(targetLook.current, LERP_FACTOR)
    camera.lookAt(currentLook.current)
  })

  return null
}

export default function EcosystemScene() {
  return (
    <div className="scene-container">
      <Canvas
        camera={{ position: [0, 2, 12], fov: 55 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
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
