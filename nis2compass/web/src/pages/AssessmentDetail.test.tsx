import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import AssessmentDetail from './AssessmentDetail'

// ---------------------------------------------------------------------------
// Mock api module and downloadAssessmentPDF
// ---------------------------------------------------------------------------

vi.mock('../api', () => ({
  api: {
    assessments: {
      get: vi.fn(),
      patch: vi.fn(),
    },
    controls: {
      list: vi.fn(),
      patch: vi.fn(),
    },
    organisations: {
      get: vi.fn(),
    },
    artifacts: {
      list: vi.fn(),
    },
    reports: {
      generate: vi.fn(),
    },
  },
  downloadAssessmentPDF: vi.fn(),
}))

import { api, downloadAssessmentPDF } from '../api'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ASSESSMENT = {
  id: 'assess-001',
  org_id: 'org-001',
  title: 'Q1 2026 NIS2 Assessment',
  status: 'in_progress' as const,
  framework_version: 'NIS2-2.0',
  scope: null,
  assessor: null,
  due_date: null,
  completed_at: null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  summary: {
    total_controls: 1,
    compliant: 1,
    partially_compliant: 0,
    non_compliant: 0,
    not_assessed: 0,
    not_applicable: 0,
    overall_risk_score: null,
  },
}

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function renderPage(assessmentId = 'assess-001') {
  return render(
    <MemoryRouter initialEntries={[`/assessments/${assessmentId}`]}>
      <Routes>
        <Route path="/assessments/:id" element={<AssessmentDetail role="admin" />} />
      </Routes>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AssessmentDetail page', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    vi.mocked(api.assessments.get).mockResolvedValue(ASSESSMENT)
    vi.mocked(api.controls.list).mockResolvedValue([])
    vi.mocked(api.organisations.get).mockResolvedValue(ORG)
    vi.mocked(api.artifacts.list).mockResolvedValue([])
  })

  it('renders loading state initially', () => {
    // Make the first call hang so we see the loading state
    vi.mocked(api.assessments.get).mockReturnValue(new Promise(() => {}))

    renderPage()

    expect(screen.getByText(/loading assessment/i)).toBeInTheDocument()
  })

  it('renders assessment title after data loads', async () => {
    renderPage()

    await waitFor(() =>
      expect(screen.getByText('Q1 2026 NIS2 Assessment')).toBeInTheDocument(),
    )
  })

  it('"Download PDF Report" button is present', async () => {
    renderPage()

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: /download pdf report/i }),
      ).toBeInTheDocument(),
    )
  })

  it('download button triggers fetch to correct URL', async () => {
    const pdfBlob = new Blob(['%PDF'], { type: 'application/pdf' })
    vi.mocked(downloadAssessmentPDF).mockResolvedValueOnce(pdfBlob)

    // Stub browser download helpers
    const mockObjectURL = 'blob:mock-url'
    URL.createObjectURL = vi.fn().mockReturnValue(mockObjectURL)
    URL.revokeObjectURL = vi.fn()

    renderPage()

    const btn = await screen.findByRole('button', { name: /download pdf report/i })
    fireEvent.click(btn)

    await waitFor(() =>
      expect(downloadAssessmentPDF).toHaveBeenCalledWith('assess-001'),
    )
  })

  it('shows error message when PDF download fails', async () => {
    vi.mocked(downloadAssessmentPDF).mockRejectedValueOnce(
      new Error('Server error'),
    )

    renderPage()

    const btn = await screen.findByRole('button', { name: /download pdf report/i })
    fireEvent.click(btn)

    await waitFor(() =>
      expect(screen.getByText(/server error/i)).toBeInTheDocument(),
    )
  })
})
