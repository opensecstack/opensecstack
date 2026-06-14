export const colors = {
  cyan:       '#00f0ff',
  magenta:    '#e040fb',
  violet:     '#7c3aed',
  blue:       '#2563eb',
  green:      '#10b981',
  amber:      '#f59e0b',
  red:        '#ef4444',
  bg:         '#050510',
  bgCard:     '#0d0d1f',
  bgGlass:    'rgba(13, 13, 31, 0.7)',
  border:     'rgba(0, 240, 255, 0.15)',
  text:       '#e2e8f0',
  textMuted:  '#94a3b8',
  textBright: '#ffffff',
} as const

export type PlatformColor = typeof colors[keyof typeof colors]
