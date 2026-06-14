import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { SeverityBadge } from './SeverityBadge'

describe('SeverityBadge', () => {
  it('renders the severity label in uppercase', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('applies the correct colour for critical', () => {
    render(<SeverityBadge severity="critical" />)
    const el = screen.getByText('critical')
    expect(el).toHaveStyle({ color: '#ef4444' })
  })

  it('applies the correct colour for high', () => {
    render(<SeverityBadge severity="high" />)
    const el = screen.getByText('high')
    expect(el).toHaveStyle({ color: '#f97316' })
  })

  it('applies the correct colour for medium', () => {
    render(<SeverityBadge severity="medium" />)
    const el = screen.getByText('medium')
    expect(el).toHaveStyle({ color: '#eab308' })
  })

  it('applies the correct colour for low', () => {
    render(<SeverityBadge severity="low" />)
    const el = screen.getByText('low')
    expect(el).toHaveStyle({ color: '#22c55e' })
  })

  it('applies the correct colour for info', () => {
    render(<SeverityBadge severity="info" />)
    const el = screen.getByText('info')
    expect(el).toHaveStyle({ color: '#3b82f6' })
  })

  it('renders as a span element', () => {
    const { container } = render(<SeverityBadge severity="high" />)
    expect(container.firstChild?.nodeName).toBe('SPAN')
  })
})
