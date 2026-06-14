import { useState, useEffect } from 'react'

export function useWebGL(): boolean {
  const [supported, setSupported] = useState(true)

  useEffect(() => {
    try {
      const canvas = document.createElement('canvas')
      const ok = !!(canvas.getContext('webgl2') || canvas.getContext('webgl'))
      setSupported(ok)
    } catch {
      setSupported(false)
    }
  }, [])

  return supported
}
