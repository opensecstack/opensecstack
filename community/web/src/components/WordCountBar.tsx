interface WordCountBarProps {
  words: number
  characters: number
  readingMinutes: number
}

export default function WordCountBar({ words, characters, readingMinutes }: WordCountBarProps) {
  if (words === 0) return null

  return (
    <p className="text-xs text-gray-400 dark:text-gray-500 text-right py-1 px-2">
      {words.toLocaleString()} words&nbsp;&nbsp;·&nbsp;&nbsp;{characters.toLocaleString()} chars&nbsp;&nbsp;·&nbsp;&nbsp;~{readingMinutes} min read
    </p>
  )
}
