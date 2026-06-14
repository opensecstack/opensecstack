import { useMemo } from 'react'

export interface WordCountStats {
  words: number
  characters: number
  readingMinutes: number
}

export function useWordCount(text: string): WordCountStats {
  return useMemo(() => {
    const trimmed = text.trim()
    const words = trimmed === '' ? 0 : trimmed.split(/\s+/).length
    const characters = text.length
    const readingMinutes = Math.max(1, Math.floor(words / 200))
    return { words, characters, readingMinutes }
  }, [text])
}
