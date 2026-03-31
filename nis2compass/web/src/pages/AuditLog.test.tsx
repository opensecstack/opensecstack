import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import AuditLog from './AuditLog'

// ---------------------------------------------------------------------------
// Mock api module
// ---------------------------------------------------------------------------

vi.mock('../api', () => ({
  api: {
    audit: {
      list: vi.fn(),
    },
  },
}))

import { api } from '../api'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ENTRIES = [
  {
    id: 'entry-001',
    action: 'assessment.created',
    actor: 'alice@example.com',
    resource_type: 'assessment',
    resource_id: 'asm-00000000-0001',
    risk_class: 'INFO' as const,
    metadata: {},
    object_fingerprint: null,
    prev_hash: null,
    chain_hash: 'abcdef1234567890',
    timestamp: '2026-01-15T10:30:00Z',
  },
  {
    id: 'entry-002',
    action: 'control.patched',
    actor: 'bob@example.com',
    resource_type: 'control',
    resource_id: 'ctrl-00000000-0002',
    risk_class: 'WARNING' as const,
    metadata: {},
    object_fingerprint: null,
    prev_hash: null,
    chain_hash: 'deadbeef12345678',
    timestamp: '2026-01-16T09:00:00Z',
  },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage() {
  return render(
    <MemoryRouter>
      <AuditLog />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AuditLog page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders "Audit Log" heading', () => {
    vi.mocked(api.audit.list).mockReturnValue(new Promise(() => {}))

    renderPage()

    expect(screen.getByRole('heading', { name: /audit log/i })).toBeInTheDocument()
  })

  it('renders log entries from mocked fetch', async () => {
    vi.mocked(api.audit.list).mockResolvedValue({ entries: ENTRIES, total: 2 })

    renderPage()

    await waitFor(() =>
      expect(screen.getByText('assessment.created')).toBeInTheDocument(),
    )
    expect(screen.getByText('control.patched')).toBeInTheDocument()
  })

  it('displays actor and action for each entry', async () => {
    vi.mocked(api.audit.list).mockResolvedValue({ entries: ENTRIES, total: 2 })

    renderPage()

    await waitFor(() =>
      expect(screen.getByText('alice@example.com')).toBeInTheDocument(),
    )
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    expect(screen.getByText('assessment.created')).toBeInTheDocument()
    expect(screen.getByText('control.patched')).toBeInTheDocument()
  })
})
