import { useEffect, useState } from 'react'

const QUERY = '(max-width: 480px)'

/**
 * Tracks the same 480px breakpoint index.css uses to disable pointer-events
 * on .scene-container, so the heavy WebGL scene isn't mounted at all on
 * viewports where the CSS already treats it as hidden.
 */
export function useNarrowViewport(): boolean {
  const [narrow, setNarrow] = useState(false)

  useEffect(() => {
    const mq = window.matchMedia(QUERY)
    const apply = () => setNarrow(mq.matches)
    apply()
    mq.addEventListener('change', apply)
    return () => mq.removeEventListener('change', apply)
  }, [])

  return narrow
}
