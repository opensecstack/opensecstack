import type { RefObject } from 'react'
import { useFrame } from '@react-three/fiber'
import * as THREE from 'three'

/**
 * Frame-rate independent hover-scale animation.
 *
 * Damps a mesh/group's uniform scale toward `targetScale` (or 1 when not
 * hovered) using THREE.MathUtils.damp, so the animation converges in
 * consistent wall-clock time regardless of the display's refresh rate —
 * unlike a fixed-factor `.lerp()` call, which runs faster on high-refresh
 * displays.
 *
 * @param ref            Ref to the Object3D (mesh/group) to scale.
 * @param hovered        Whether the object is currently hovered.
 * @param targetScale    Uniform scale to damp toward while hovered.
 * @param dampingFactor  Higher = snappier convergence (passed to THREE.MathUtils.damp).
 */
export function useHoverScale(
  ref: RefObject<THREE.Object3D>,
  hovered: boolean,
  targetScale = 1.15,
  dampingFactor = 8,
) {
  useFrame((_, delta) => {
    const obj = ref.current
    if (!obj) return
    const target = hovered ? targetScale : 1
    const next = THREE.MathUtils.damp(obj.scale.x, target, dampingFactor, delta)
    obj.scale.setScalar(next)
  })
}
