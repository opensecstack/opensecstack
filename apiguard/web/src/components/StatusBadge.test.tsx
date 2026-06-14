import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { StatusBadge } from './StatusBadge'

describe('StatusBadge', () => {
  const cases = [
    { status: 'completed', color: '#4ade80' },
    { status: 'failed',    color: '#f87171' },
    { status: 'running',   color: '#818cf8' },
    { status: 'pending',   color: '#94a3b8' },
    { status: 'cancelled', color: '#94a3b8' },
  ] as const

  for (const { status, color } of cases) {
    it(`renders ${status} with correct colour`, () => {
      render(<StatusBadge status={status} />)
      const el = screen.getByText(status)
      expect(el).toBeInTheDocument()
      expect(el).toHaveStyle({ color })
    })
  }

  it('renders as a span element', () => {
    const { container } = render(<StatusBadge status="completed" />)
    expect(container.firstChild?.nodeName).toBe('SPAN')
  })
})
