/**
 * Central registry for Higgsfield-generated media (video / animation / 3D
 * sequences). This is the ONLY file you edit to wire clips into the site.
 *
 * Workflow:
 *   1. Generate the clip at https://cloud.higgsfield.ai and export it.
 *   2. Drop the files into website/public/media/ using this naming convention:
 *        public/media/<name>.webm   (VP9/AV1 — smaller, preferred source)
 *        public/media/<name>.mp4    (H.264 — universal fallback)
 *        public/media/<name>.jpg    (a poster frame, shown before it loads)
 *      WebM is optional but recommended; MP4 alone works everywhere.
 *   3. Reference <name> below. Until a clip is listed here, nothing renders —
 *      the site never shows a broken or empty media slot.
 */

export interface MediaClip {
  /** Base filename under public/media/, no extension. */
  name: string
  title?: string
  caption?: string
}

/**
 * Hero background sequence. Set to a clip name to enable it, or keep null to
 * leave the hero as-is. Example: 'hero'.
 */
export const heroMedia: string | null = null

/**
 * Showcase section clips. An empty array hides the whole section.
 * Example entry:
 *   { name: 'showcase-ecosystem', title: 'The Ecosystem',
 *     caption: '11 platforms, one cryptographic governance spine.' }
 */
export const showcaseMedia: MediaClip[] = []

/**
 * Per-platform clips, keyed by platform id (see src/data/platforms.ts).
 * Only platforms listed here render a clip at the top of their card.
 * Example: { apiguard: 'platforms/apiguard' }
 */
export const platformMedia: Record<string, string> = {}
