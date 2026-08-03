import { useCallback, useMemo } from 'react'
import { translations, type TranslationKey } from './translations'

export function useI18n() {
  const t = useCallback((key: TranslationKey): string => {
    return translations[key] ?? key
  }, [])

  return useMemo(() => ({ t }), [t])
}
