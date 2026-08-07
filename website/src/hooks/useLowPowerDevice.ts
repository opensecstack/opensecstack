import { useEffect, useState } from 'react'

/**
 * Heuristic device-tier detection: a coarse pointer (touch) combined with a
 * narrow viewport, or a low logical core count, is treated as a low-powered
 * device and should get a cheaper render path (no/lighter postprocessing,
 * capped dpr, fewer particles).
 */
export function useLowPowerDevice(): boolean {
  const [lowPower, setLowPower] = useState(false)
  useEffect(() => {
    const coarsePointer = window.matchMedia('(pointer: coarse)').matches
    const narrowViewport = window.innerWidth <= 820
    const lowCores = (navigator.hardwareConcurrency ?? 8) <= 4
    setLowPower((coarsePointer && narrowViewport) || lowCores)
  }, [])
  return lowPower
}
