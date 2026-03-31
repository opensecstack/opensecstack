import { useState, useEffect, useCallback, useMemo } from 'react'
import { translations, type Language, type TranslationKey } from './translations'

const STORAGE_KEY = 'sin-lang'

function getInitialLang(): Language {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'en' || stored === 'al') return stored
  } catch {
    // localStorage unavailable
  }
  return 'en'
}

// Singleton state so all hooks share the same language.
// This is a simple approach; for production you'd use React context.
let listeners: Array<() => void> = []
let currentLang: Language = getInitialLang()

function setLang(lang: Language) {
  currentLang = lang
  try {
    localStorage.setItem(STORAGE_KEY, lang)
  } catch {
    // ignore
  }
  listeners.forEach(fn => fn())
}

export function useI18n() {
  const [lang, setLangState] = useState<Language>(currentLang)

  // Subscribe to global lang changes
  useEffect(() => {
    const handler = () => setLangState(currentLang)
    listeners.push(handler)
    return () => {
      listeners = listeners.filter(l => l !== handler)
    }
  }, [])

  const t = useCallback(
    (key: TranslationKey): string => {
      return translations[lang]?.[key] ?? translations.en[key] ?? key
    },
    [lang],
  )

  const toggle = useCallback(() => {
    const next: Language = currentLang === 'en' ? 'al' : 'en'
    setLang(next)
  }, [])

  return useMemo(() => ({ lang, t, toggle }), [lang, t, toggle])
}
