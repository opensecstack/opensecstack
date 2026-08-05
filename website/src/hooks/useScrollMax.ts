import { useEffect, useRef } from 'react'

/**
 * Caches `document.documentElement.scrollHeight - window.innerHeight`
 * (the maximum scrollY value) in a ref, recomputed only on resize/content
 * changes rather than every frame — scrollHeight is a layout-triggering
 * read, so callers driving per-frame scroll-progress math (e.g. inside
 * useFrame) should read `window.scrollY / scrollMax.current` instead of
 * recomputing the max each frame.
 */
export function useScrollMax() {
  const scrollMax = useRef(1)

  useEffect(() => {
    const update = () => {
      scrollMax.current = Math.max(
        1,
        document.documentElement.scrollHeight - window.innerHeight,
      )
    }
    update()

    window.addEventListener('resize', update)

    let resizeObserver: ResizeObserver | undefined
    if (typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(update)
      resizeObserver.observe(document.documentElement)
    }

    return () => {
      window.removeEventListener('resize', update)
      resizeObserver?.disconnect()
    }
  }, [])

  return scrollMax
}
