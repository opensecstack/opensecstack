/**
 * Shared orbital-position formula used by the fortress orbital nodes and
 * their connecting edges, so the two stay perfectly attached without
 * duplicating the math.
 *
 * NOTE: src/scene/DataFlowPackets.tsx still has its own inline copy of an
 * equivalent formula (outside this pass's file ownership) — it should
 * eventually be migrated to use this helper too.
 */
export interface OrbitPosition {
  x: number
  y: number
  z: number
}

/**
 * Computes a point orbiting the origin on the XZ plane, with a secondary
 * vertical bob, given elapsed time, a per-node base angle, and orbit radius.
 */
export function getOrbitPosition(elapsed: number, angle: number, radius: number): OrbitPosition {
  const t = elapsed * 0.08 + angle
  return {
    x: Math.cos(t) * radius,
    y: Math.sin(t * 2) * 0.3,
    z: Math.sin(t) * radius,
  }
}
