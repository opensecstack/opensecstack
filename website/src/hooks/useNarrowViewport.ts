import { useEffect, useState } from 'react'

const QUERY = '(max-width: 480px)'

/**
 * Tracks the same 480px breakpoint index.css uses to disable pointer-events
 * on .scene-container, so the heavy WebGL scene isn't mounted at all on
 * viewports where the CSS already treats it as hidden.
 *
 * The initial state is read synchronously from matchMedia (not in an effect)
 * so the first render already reflects the real viewport — otherwise the
 * heavy desktop scene mounts for one paint on every load before the effect
 * below can flip it off, causing jank on mobile.
 */
export function useNarrowViewport(): boolean {
  const [narrow, setNarrow] = useState(
    () => typeof window !== 'undefined' && window.matchMedia(QUERY).matches,
  )

  useEffect(() => {
    const mq = window.matchMedia(QUERY)
    const apply = () => setNarrow(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])

  return narrow
}
