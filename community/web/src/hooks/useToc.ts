import { useState, useEffect, type RefObject } from "react"

export interface TocEntry {
  id: string
  text: string
  level: 2 | 3
}

export function useToc(contentRef: RefObject<HTMLElement>) {
  const [entries, setEntries] = useState<TocEntry[]>([])
  const [activeId, setActiveId] = useState<string>("")

  useEffect(() => {
    const el = contentRef.current
    if (!el) return

    // Find all h2 and h3 elements
    const headings = Array.from(el.querySelectorAll("h2, h3")) as HTMLElement[]

    // Assign IDs if missing (slug from text)
    headings.forEach((h) => {
      if (!h.id) {
        h.id =
          h.textContent
            ?.toLowerCase()
            .replace(/[^a-z0-9]+/g, "-")
            .replace(/^-|-$/g, "") ?? ""
      }
    })

    setEntries(
      headings.map((h) => ({
        id: h.id,
        text: h.textContent ?? "",
        level: parseInt(h.tagName[1]) as 2 | 3,
      }))
    )

    // IntersectionObserver: mark active heading when it crosses into view
    const observer = new IntersectionObserver(
      (observerEntries) => {
        const visible = observerEntries.find((e) => e.isIntersecting)
        if (visible) setActiveId(visible.target.id)
      },
      { rootMargin: "-10% 0px -80% 0px" }
    )
    headings.forEach((h) => observer.observe(h))
    return () => observer.disconnect()
  }, [contentRef])

  return { entries, activeId }
}
