import { Suspense, useEffect, useState } from 'react'
import { Canvas } from '@react-three/fiber'
import { Stars } from '@react-three/drei'
import { EffectComposer, Bloom, Vignette } from '@react-three/postprocessing'
import MobileDevice from './platforms/MobileDevice'
import { useLowPowerDevice } from '../hooks/useLowPowerDevice'

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

export default function MobileScene() {
  const lowPower = useLowPowerDevice()
  const reducedMotion = usePrefersReducedMotion()

  return (
    <div className="scene-container">
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        dpr={lowPower ? [1, 1] : [1, 1.5]}
        gl={{ antialias: !lowPower, alpha: true }}
      >
        <ambientLight intensity={0.1} />
        <pointLight position={[4, 4, 4]} intensity={0.3} color="#10b981" />
        <pointLight position={[-4, -2, -4]} intensity={0.15} color="#3b82f6" />

        <Suspense fallback={null}>
          <Stars
            radius={80}
            depth={40}
            count={lowPower ? 500 : 1500}
            factor={3}
            saturation={0}
            fade
            speed={reducedMotion ? 0 : 0.3}
          />
          <group position={[3, 0, 0]} scale={[0.6, 0.6, 0.6]}>
            <MobileDevice />
          </group>
          {!lowPower && (
            <EffectComposer>
              <Bloom luminanceThreshold={0.4} luminanceSmoothing={0.9} intensity={0.5} />
              <Vignette eskil={false} offset={0.1} darkness={0.5} />
            </EffectComposer>
          )}
        </Suspense>
      </Canvas>
    </div>
  )
}
