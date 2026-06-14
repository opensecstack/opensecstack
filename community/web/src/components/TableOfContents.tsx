import type { MouseEvent } from "react"
import type { TocEntry } from "@/hooks/useToc"

interface Props {
  entries: TocEntry[]
  activeId: string
}

export default function TableOfContents({ entries, activeId }: Props) {
  if (entries.length < 3) return null

  function handleClick(e: MouseEvent<HTMLAnchorElement>, id: string) {
    e.preventDefault()
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" })
  }

  return (
    <nav aria-label="Table of contents">
      <p className="text-xs font-semibold uppercase tracking-widest text-gray-400 dark:text-gray-500 mb-3">
        Contents
      </p>
      <ul
        className="space-y-1 max-h-[70vh] overflow-y-auto pr-1"
        style={{ scrollbarWidth: "thin" }}
      >
        {entries.map((entry) => {
          const isActive = entry.id === activeId
          return (
            <li key={entry.id} className={entry.level === 3 ? "pl-4" : ""}>
              <a
                href={`#${entry.id}`}
                onClick={(e) => handleClick(e, entry.id)}
                className={[
                  "block text-sm py-0.5 border-l-2 pl-2 transition-colors leading-snug",
                  isActive
                    ? "border-indigo-500 text-indigo-600 dark:text-indigo-400 font-medium"
                    : "border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-800 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600",
                ].join(" ")}
              >
                {entry.text}
              </a>
            </li>
          )
        })}
      </ul>
    </nav>
  )
}
