import { EffectComposer, Bloom, Vignette, DepthOfField } from '@react-three/postprocessing'
import { useLowPowerDevice } from '../../hooks/useLowPowerDevice'

/**
 * On capable devices, layers a stronger, more cinematic Bloom plus a
 * DepthOfField pass (background softly blurred, CitadelFortress roughly in
 * focus) on top of the baseline Bloom+Vignette treatment -- the "dense
 * glow + blurred depth" look. Low-power devices (see useLowPowerDevice) get
 * the original, cheaper Bloom+Vignette-only setup: DepthOfField in
 * particular is one of the more expensive full-screen passes available, not
 * worth its cost on constrained GPUs for a purely decorative effect.
 */
export default function Effects() {
  const lowPower = useLowPowerDevice()

  if (lowPower) {
    return (
      <EffectComposer>
        <Bloom luminanceThreshold={0.6} luminanceSmoothing={0.9} intensity={0.4} />
        <Vignette eskil={false} offset={0.1} darkness={0.5} />
      </EffectComposer>
    )
  }

  return (
    <EffectComposer>
      <Bloom luminanceThreshold={0.35} luminanceSmoothing={0.7} intensity={1.1} mipmapBlur radius={0.8} />
      <DepthOfField focusDistance={0.012} focalLength={0.04} bokehScale={3} />
      <Vignette eskil={false} offset={0.15} darkness={0.6} />
    </EffectComposer>
  )
}
