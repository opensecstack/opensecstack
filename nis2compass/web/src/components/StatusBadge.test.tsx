import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusBadge } from './StatusBadge'

// ---------------------------------------------------------------------------
// Assessment statuses
// ---------------------------------------------------------------------------

describe('StatusBadge — assessment statuses', () => {
  it('renders "draft" as-is (no label override)', () => {
    render(<StatusBadge status="draft" />)
    expect(screen.getByText('draft')).toBeInTheDocument()
  })

  it('renders "in_progress" as "In Progress"', () => {
    render(<StatusBadge status="in_progress" />)
    expect(screen.getByText('In Progress')).toBeInTheDocument()
  })

  it('renders "under_review" as "Under Review"', () => {
    render(<StatusBadge status="under_review" />)
    expect(screen.getByText('Under Review')).toBeInTheDocument()
  })

  it('renders "completed" as-is', () => {
    render(<StatusBadge status="completed" />)
    expect(screen.getByText('completed')).toBeInTheDocument()
  })

  it('renders "archived" as-is', () => {
    render(<StatusBadge status="archived" />)
    expect(screen.getByText('archived')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Control statuses
// ---------------------------------------------------------------------------

describe('StatusBadge — control statuses', () => {
  it('renders "not_assessed" as "Not Assessed"', () => {
    render(<StatusBadge status="not_assessed" />)
    expect(screen.getByText('Not Assessed')).toBeInTheDocument()
  })

  it('renders "compliant" as-is', () => {
    render(<StatusBadge status="compliant" />)
    expect(screen.getByText('compliant')).toBeInTheDocument()
  })

  it('renders "partially_compliant" as "Partial"', () => {
    render(<StatusBadge status="partially_compliant" />)
    expect(screen.getByText('Partial')).toBeInTheDocument()
  })

  it('renders "non_compliant" as "Non-Compliant"', () => {
    render(<StatusBadge status="non_compliant" />)
    expect(screen.getByText('Non-Compliant')).toBeInTheDocument()
  })

  it('renders "not_applicable" as "N/A"', () => {
    render(<StatusBadge status="not_applicable" />)
    expect(screen.getByText('N/A')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Risk classes
// ---------------------------------------------------------------------------

describe('StatusBadge — risk classes', () => {
  const cases = [
    { status: 'INFO'     as const, color: '#60a5fa' },
    { status: 'WARNING'  as const, color: '#fcd34d' },
    { status: 'CRITICAL' as const, color: '#f87171' },
  ]

  for (const { status, color } of cases) {
    it(`renders ${status} with correct colour`, () => {
      render(<StatusBadge status={status} />)
      const el = screen.getByText(status)
      expect(el).toBeInTheDocument()
      expect(el).toHaveStyle({ color })
    })
  }
})

// ---------------------------------------------------------------------------
// Colour mapping spot-checks
// ---------------------------------------------------------------------------

describe('StatusBadge — colour mapping', () => {
  it('non_compliant uses red', () => {
    render(<StatusBadge status="non_compliant" />)
    expect(screen.getByText('Non-Compliant')).toHaveStyle({ color: '#f87171' })
  })

  it('compliant uses green', () => {
    render(<StatusBadge status="compliant" />)
    expect(screen.getByText('compliant')).toHaveStyle({ color: '#4ade80' })
  })

  it('partially_compliant uses yellow', () => {
    render(<StatusBadge status="partially_compliant" />)
    expect(screen.getByText('Partial')).toHaveStyle({ color: '#fcd34d' })
  })

  it('renders as a span element', () => {
    const { container } = render(<StatusBadge status="compliant" />)
    expect(container.firstChild?.nodeName).toBe('SPAN')
  })
})
