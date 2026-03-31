import { useState, useCallback, useEffect } from 'react'

type Mode = 'dark' | 'light'

const STORAGE_KEY = 'oss-theme'

function getInitialMode(): Mode {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark') return stored
  } catch {
    // localStorage may be unavailable
  }
  return 'dark'
}

function applyMode(mode: Mode) {
  if (mode === 'light') {
    document.body.classList.add('light-mode')
  } else {
    document.body.classList.remove('light-mode')
  }
}

export function useThemeToggle() {
  const [mode, setMode] = useState<Mode>(() => {
    const initial = getInitialMode()
    applyMode(initial)
    return initial
  })

  // Keep body class in sync whenever mode changes
  useEffect(() => {
    applyMode(mode)
  }, [mode])

  const toggle = useCallback(() => {
    setMode(prev => {
      const next: Mode = prev === 'dark' ? 'light' : 'dark'
      try {
        localStorage.setItem(STORAGE_KEY, next)
      } catch {
        // ignore
      }
      return next
    })
  }, [])

  return { mode, toggle }
}
