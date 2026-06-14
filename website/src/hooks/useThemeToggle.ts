import { useState, useCallback, useEffect } from 'react'

export type Theme = 'light' | 'dark' | 'system'
type Resolved = 'light' | 'dark'

const STORAGE_KEY = 'oss-theme'

function getStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'light' || stored === 'dark' || stored === 'system') return stored
  } catch {
    // localStorage may be unavailable
  }
  // Preserve the original dark-first default when nothing is stored.
  return 'dark'
}

function systemPrefersDark(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )
}

function resolveTheme(theme: Theme): Resolved {
  if (theme === 'system') return systemPrefersDark() ? 'dark' : 'light'
  return theme
}

function applyResolved(resolved: Resolved) {
  if (resolved === 'light') {
    document.body.classList.add('light-mode')
  } else {
    document.body.classList.remove('light-mode')
  }
}

export function useThemeToggle() {
  const [theme, setThemeState] = useState<Theme>(() => {
    const initial = getStoredTheme()
    applyResolved(resolveTheme(initial))
    return initial
  })
  const [resolved, setResolved] = useState<Resolved>(() => resolveTheme(getStoredTheme()))

  // Apply whenever the chosen theme changes.
  useEffect(() => {
    const r = resolveTheme(theme)
    setResolved(r)
    applyResolved(r)
  }, [theme])

  // When following the system, react to OS-level scheme changes live.
  useEffect(() => {
    if (theme !== 'system') return
    if (typeof window.matchMedia !== 'function') return
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => {
      const r: Resolved = mq.matches ? 'dark' : 'light'
      setResolved(r)
      applyResolved(r)
    }
    mq.addEventListener('change', onChange)
    return () => mq.removeEventListener('change', onChange)
  }, [theme])

  const setTheme = useCallback((next: Theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // ignore
    }
    setThemeState(next)
  }, [])

  return { theme, resolved, setTheme }
}
