import { Suspense } from 'react'
import { Canvas } from '@react-three/fiber'
import CitadelFortress from './CitadelFortress'
import OrbitalRing from './OrbitalRing'
import WormChainEdges from './WormChainEdges'
import ParticleGrid from './ParticleGrid'
import TechParticles from './TechParticles'
import Effects from './postprocessing/Effects'

export default function EcosystemScene() {
  return (
    <div className="scene-container">
      <Canvas
        camera={{ position: [0, 2, 12], fov: 55 }}
        dpr={[1, 1.5]}
        gl={{ antialias: true, alpha: true }}
      >
        <ambientLight intensity={0.15} />
        <pointLight position={[10, 10, 10]} intensity={0.3} color="#00f0ff" />
        <pointLight position={[-10, -5, -10]} intensity={0.15} color="#7c3aed" />

        <Suspense fallback={null}>
          <ParticleGrid />
          <TechParticles />
          <CitadelFortress />
          <OrbitalRing />
          <WormChainEdges />
          <Effects />
        </Suspense>
      </Canvas>
    </div>
  )
}
