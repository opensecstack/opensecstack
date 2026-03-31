/**
 * 2D point clouds that approximate programming language logos.
 * Each shape is ~300 points sampled to fill the icon outline.
 * Points are in [-1, 1] normalized space.
 *
 * At runtime, particles are assigned to these target positions
 * and lerp toward them to "form" the logo shape.
 */

type Point2D = [number, number]

/** Sample N points along a line segment */
function line(x1: number, y1: number, x2: number, y2: number, n: number): Point2D[] {
  const pts: Point2D[] = []
  for (let i = 0; i < n; i++) {
    const t = i / (n - 1)
    pts.push([x1 + (x2 - x1) * t, y1 + (y2 - y1) * t])
  }
  return pts
}

/** Sample N points along a circle arc */
function arc(cx: number, cy: number, r: number, startAngle: number, endAngle: number, n: number): Point2D[] {
  const pts: Point2D[] = []
  for (let i = 0; i < n; i++) {
    const t = i / (n - 1)
    const a = startAngle + (endAngle - startAngle) * t
    pts.push([cx + Math.cos(a) * r, cy + Math.sin(a) * r])
  }
  return pts
}

/** Sample N points filling a circle (disk) */
function disk(cx: number, cy: number, r: number, n: number): Point2D[] {
  const pts: Point2D[] = []
  for (let i = 0; i < n; i++) {
    const angle = (i / n) * Math.PI * 2 * 7.3 // golden-ish spread
    const radius = r * Math.sqrt(i / n)
    pts.push([cx + Math.cos(angle) * radius, cy + Math.sin(angle) * radius])
  }
  return pts
}

/** Fill a rectangle with points */
function rect(x: number, y: number, w: number, h: number, n: number): Point2D[] {
  const pts: Point2D[] = []
  const cols = Math.ceil(Math.sqrt(n * w / h))
  const rows = Math.ceil(n / cols)
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      if (pts.length >= n) break
      pts.push([x + (c / (cols - 1)) * w, y + (r / (rows - 1)) * h])
    }
  }
  return pts.slice(0, n)
}

// ─── GO: "Go" text shape ─────────────────────────────────────────────

function makeGoShape(): Point2D[] {
  const pts: Point2D[] = []
  // "G" letter
  pts.push(...arc(-0.4, 0, 0.45, -0.3, Math.PI + 0.3, 60))       // C-shape arc
  pts.push(...line(-0.05, 0, 0.05, 0, 15))                         // horizontal bar
  pts.push(...line(0.05, 0, 0.05, -0.25, 12))                      // right vertical
  // Fill the G interior slightly
  pts.push(...arc(-0.4, 0, 0.3, -0.2, Math.PI + 0.2, 30))

  // "o" letter
  pts.push(...arc(0.45, -0.05, 0.32, 0, Math.PI * 2, 55))         // outer ring
  pts.push(...arc(0.45, -0.05, 0.2, 0, Math.PI * 2, 35))          // inner ring
  pts.push(...disk(0.45, -0.05, 0.1, 20))                          // center fill

  // Gopher eyes (two dots above)
  pts.push(...disk(-0.15, 0.55, 0.08, 15))
  pts.push(...disk(0.15, 0.55, 0.08, 15))

  return pts // ~257 points
}

// ─── RUST: Gear/cog shape ────────────────────────────────────────────

function makeRustShape(): Point2D[] {
  const pts: Point2D[] = []
  const teeth = 12
  const outerR = 0.7
  const innerR = 0.5

  // Gear outline
  for (let i = 0; i < teeth; i++) {
    const a1 = (i / teeth) * Math.PI * 2
    const a2 = ((i + 0.3) / teeth) * Math.PI * 2
    const a3 = ((i + 0.5) / teeth) * Math.PI * 2
    const a4 = ((i + 0.8) / teeth) * Math.PI * 2
    pts.push(...line(
      Math.cos(a1) * innerR, Math.sin(a1) * innerR,
      Math.cos(a2) * outerR, Math.sin(a2) * outerR, 4
    ))
    pts.push(...line(
      Math.cos(a2) * outerR, Math.sin(a2) * outerR,
      Math.cos(a3) * outerR, Math.sin(a3) * outerR, 4
    ))
    pts.push(...line(
      Math.cos(a3) * outerR, Math.sin(a3) * outerR,
      Math.cos(a4) * innerR, Math.sin(a4) * innerR, 4
    ))
  }

  // Inner circle
  pts.push(...arc(0, 0, 0.28, 0, Math.PI * 2, 40))
  // Center dot
  pts.push(...disk(0, 0, 0.12, 25))
  // "R" letter inside
  pts.push(...line(-0.08, -0.15, -0.08, 0.15, 12))  // vertical
  pts.push(...arc(-0.01, 0.07, 0.08, -Math.PI / 2, Math.PI / 2, 10)) // bump
  pts.push(...line(-0.08, 0, 0.05, -0.15, 8))         // leg

  return pts // ~253 points
}

// ─── PYTHON: Two intertwined snakes ──────────────────────────────────

function makePythonShape(): Point2D[] {
  const pts: Point2D[] = []

  // Top snake (blue half)
  pts.push(...arc(-0.1, 0.25, 0.35, Math.PI * 0.5, Math.PI * 1.5, 40))
  pts.push(...line(-0.1, 0.6, 0.35, 0.6, 20))
  pts.push(...arc(0.35, 0.42, 0.18, Math.PI * 0.5, -Math.PI * 0.5, 20))
  pts.push(...line(0.35, 0.24, 0, 0.24, 15))
  // Top snake body fill
  pts.push(...rect(-0.35, 0.25, 0.5, 0.35, 40))
  // Top eye
  pts.push(...disk(-0.15, 0.45, 0.05, 10))

  // Bottom snake (yellow half) — mirrored
  pts.push(...arc(0.1, -0.25, 0.35, -Math.PI * 0.5, Math.PI * 0.5, 40))
  pts.push(...line(0.1, -0.6, -0.35, -0.6, 20))
  pts.push(...arc(-0.35, -0.42, 0.18, -Math.PI * 0.5, Math.PI * 0.5, 20))
  pts.push(...line(-0.35, -0.24, 0, -0.24, 15))
  // Bottom snake body fill
  pts.push(...rect(-0.15, -0.6, 0.5, 0.35, 40))
  // Bottom eye
  pts.push(...disk(0.15, -0.45, 0.05, 10))

  return pts // ~290 points
}

// ─── TYPESCRIPT: "TS" in a rounded rectangle ─────────────────────────

function makeTSShape(): Point2D[] {
  const pts: Point2D[] = []

  // Rounded rectangle border
  const s = 0.7
  pts.push(...line(-s, -s, s, -s, 20))   // bottom
  pts.push(...line(s, -s, s, s, 20))     // right
  pts.push(...line(s, s, -s, s, 20))     // top
  pts.push(...line(-s, s, -s, -s, 20))   // left

  // Inner fill (sparse)
  pts.push(...rect(-0.6, -0.6, 1.2, 1.2, 40))

  // "T" letter
  pts.push(...line(-0.55, 0.35, 0, 0.35, 18))         // top bar
  pts.push(...line(-0.28, 0.35, -0.28, -0.4, 25))      // vertical stem

  // "S" letter
  pts.push(...arc(0.3, 0.15, 0.2, Math.PI * 0.3, Math.PI * 1.2, 25))   // top curve
  pts.push(...arc(0.3, -0.15, 0.2, -Math.PI * 0.7, Math.PI * 0.2, 25)) // bottom curve

  return pts // ~213 points
}

// ─── TERRAFORM: Diamond/polygon shape ────────────────────────────────

function makeTerraformShape(): Point2D[] {
  const pts: Point2D[] = []

  // Three parallelogram blocks (Terraform logo)
  // Left block
  const bw = 0.35, bh = 0.4, gap = 0.08

  // Top-left parallelogram
  pts.push(...rect(-0.5, 0.1, bw, bh, 45))
  pts.push(...line(-0.5, 0.1, -0.15, 0.1, 10))
  pts.push(...line(-0.5, 0.5, -0.15, 0.5, 10))

  // Top-right parallelogram
  pts.push(...rect(gap, 0.1, bw, bh, 45))
  pts.push(...line(gap, 0.1, gap + bw, 0.1, 10))
  pts.push(...line(gap, 0.5, gap + bw, 0.5, 10))

  // Bottom-left (the detached one)
  pts.push(...rect(-0.5, -0.55, bw, bh, 45))
  pts.push(...line(-0.5, -0.55, -0.15, -0.55, 10))
  pts.push(...line(-0.5, -0.15, -0.15, -0.15, 10))

  // Bottom-right parallelogram
  pts.push(...rect(gap, -0.55, bw, bh, 45))
  pts.push(...line(gap, -0.55, gap + bw, -0.55, 10))
  pts.push(...line(gap, -0.15, gap + bw, -0.15, 10))

  return pts // ~260 points
}

// ─── Export all shapes ───────────────────────────────────────────────

export interface IconShape {
  label: string
  color: string
  points: Point2D[]
}

export const iconShapes: IconShape[] = [
  { label: 'Go',         color: '#00ADD8', points: makeGoShape() },
  { label: 'Rust',       color: '#CE422B', points: makeRustShape() },
  { label: 'Python',     color: '#3776AB', points: makePythonShape() },
  { label: 'TypeScript', color: '#3178C6', points: makeTSShape() },
  { label: 'Terraform',  color: '#7B42BC', points: makeTerraformShape() },
]
