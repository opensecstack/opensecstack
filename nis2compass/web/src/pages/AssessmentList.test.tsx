import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AssessmentList from './AssessmentList'

// ---------------------------------------------------------------------------
// Mock api module
// ---------------------------------------------------------------------------

vi.mock('../api', () => ({
  api: {
    organisations: {
      get: vi.fn(),
    },
    assessments: {
      list: vi.fn(),
      create: vi.fn(),
    },
  },
}))

import { api } from '../api'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ORG = {
  id: 'org-001',
  name: 'Acme Corp',
  industry: 'energy',
  country: 'DE',
  size: 'medium' as const,
  entity_type: 'essential' as const,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

const ASSESSMENTS = [
  {
    id: 'asm-001',
    org_id: 'org-001',
    title: 'Q1 2026 NIS2 Assessment',
    status: 'in_progress' as const,
    framework_version: 'NIS2-2.0',
    scope: null,
    assessor: 'alice@example.com',
    due_date: '2026-03-31',
    completed_at: null,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  },
  {
    id: 'asm-002',
    org_id: 'org-001',
    title: 'Q2 2026 Follow-up',
    status: 'draft' as const,
    framework_version: 'NIS2-2.0',
    scope: null,
    assessor: null,
    due_date: null,
    completed_at: null,
    created_at: '2026-04-01T00:00:00Z',
    updated_at: '2026-04-01T00:00:00Z',
  },
]

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage(orgId = 'org-001') {
  return render(
    <MemoryRouter initialEntries={[`/organisations/${orgId}/assessments`]}>
      <Routes>
        <Route path="/organisations/:orgId/assessments" element={<AssessmentList />} />
        <Route path="/assessments/:id" element={<div>Assessment Detail</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AssessmentList page', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.organisations.get).mockResolvedValue(ORG)
  })

  it('renders "No assessments" when list is empty', async () => {
    vi.mocked(api.assessments.list).mockResolvedValue([])

    renderPage()

    await waitFor(() =>
      expect(screen.getByText(/no assessments yet/i)).toBeInTheDocument(),
    )
  })

  it('renders assessment rows when data is present', async () => {
    vi.mocked(api.assessments.list).mockResolvedValue(ASSESSMENTS)

    renderPage()

    await waitFor(() =>
      expect(screen.getByText('Q1 2026 NIS2 Assessment')).toBeInTheDocument(),
    )
    expect(screen.getByText('Q2 2026 Follow-up')).toBeInTheDocument()
  })

  it('clicking a row "Open" link navigates to the detail page', async () => {
    vi.mocked(api.assessments.list).mockResolvedValue(ASSESSMENTS)

    renderPage()

    const openLinks = await screen.findAllByRole('link', { name: /open/i })
    expect(openLinks[0]).toHaveAttribute('href', '/assessments/asm-001')
  })
})
