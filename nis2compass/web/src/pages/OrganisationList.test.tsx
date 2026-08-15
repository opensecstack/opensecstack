import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import OrganisationList from './OrganisationList'

// ---------------------------------------------------------------------------
// Mock api module
// ---------------------------------------------------------------------------

vi.mock('../api', () => ({
  api: {
    organisations: {
      list: vi.fn(),
      create: vi.fn(),
    },
  },
}))

import { api } from '../api'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORGS = [
  {
    id: 'org-001',
    name: 'Acme Corp',
    industry: 'energy',
    country: 'DE',
    size: 'medium' as const,
    entity_type: 'essential' as const,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'org-002',
    name: 'Beta Transport GmbH',
    industry: 'transport',
    country: 'AT',
    size: 'large' as const,
    entity_type: 'important' as const,
    created_at: '2026-02-01T00:00:00Z',
    updated_at: '2026-02-01T00:00:00Z',
  },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage() {
  return render(
    <MemoryRouter>
      <OrganisationList role="admin" />
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('OrganisationList page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders page heading', async () => {
    vi.mocked(api.organisations.list).mockResolvedValue([])

    renderPage()

    expect(screen.getByRole('heading', { name: /organisations/i })).toBeInTheDocument()
  })

  it('renders organisation names from mocked API response', async () => {
    vi.mocked(api.organisations.list).mockResolvedValue(ORGS)

    renderPage()

    await waitFor(() =>
      expect(screen.getByText('Acme Corp')).toBeInTheDocument(),
    )
    expect(screen.getByText('Beta Transport GmbH')).toBeInTheDocument()
  })

  it('shows loading indicator while fetching', () => {
    // Make the call hang so we observe the loading state
    vi.mocked(api.organisations.list).mockReturnValue(new Promise(() => {}))

    renderPage()

    expect(screen.getByText(/loading organisations/i)).toBeInTheDocument()
  })
})
