import { useEffect, useRef } from 'react'
import type { CSSProperties } from 'react'

interface Props {
  /** Base filename under public/media/ without extension (e.g. 'hero' or 'platforms/apiguard'). */
  name: string
  /** 'background' = decorative, muted, autoplay, hidden from assistive tech.
   *  'content' = a showcased clip the user is meant to watch. */
  variant?: 'background' | 'content'
  /** Render the poster frame (public/media/<name>.jpg) before/while the video loads. */
  poster?: boolean
  className?: string
  style?: CSSProperties
}

const BASE = '/media'

/**
 * Renders a Higgsfield-generated clip with a WebM source (smaller, preferred)
 * and an MP4 fallback (universal). Background clips honour the user's
 * prefers-reduced-motion setting: when motion is reduced they hold on the
 * poster frame instead of autoplaying.
 */
export default function MediaVideo({
  name,
  variant = 'content',
  poster = true,
  className,
  style,
}: Props) {
  const ref = useRef<HTMLVideoElement>(null)
  const isBackground = variant === 'background'

  useEffect(() => {
    if (!isBackground) return
    const el = ref.current
    if (!el) return
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)')
    const apply = () => {
      if (reduce.matches) el.pause()
      else void el.play().catch(() => {/* autoplay can be blocked; poster remains */})
    }
    apply()
    reduce.addEventListener('change', apply)
    return () => reduce.removeEventListener('change', apply)
  }, [isBackground])

  return (
    <video
      ref={ref}
      autoPlay={!isBackground}
      muted
      loop
      playsInline
      preload={isBackground ? 'auto' : 'metadata'}
      controls={variant === 'content'}
      poster={poster ? `${BASE}/${name}.jpg` : undefined}
      aria-hidden={isBackground}
      className={className}
      style={style}
    >
      <source src={`${BASE}/${name}.webm`} type="video/webm" />
      <source src={`${BASE}/${name}.mp4`} type="video/mp4" />
    </video>
  )
}
