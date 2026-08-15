import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { api } from './api'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockFetch(status: number, body: unknown, headers?: Record<string, string>) {
  const responseHeaders = new Headers(headers)
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: responseHeaders,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
    blob: () => Promise.resolve(new Blob()),
  })
}

const TOKEN_KEY = 'nis2compass_token'

beforeEach(() => {
  localStorage.clear()
})
afterEach(() => {
  localStorage.clear()
})

// ---------------------------------------------------------------------------
// auth.login
// ---------------------------------------------------------------------------

describe('api.auth.login', () => {
  it('returns the token on success', async () => {
    globalThis.fetch = mockFetch(200, { access_token: 'tok-nis2' })
    const token = await api.auth.login('nis2_apk_test')
    expect(token).toBe('tok-nis2')
  })

  it('POSTs to /api/v1/auth/token with api_key in body', async () => {
    const fetchMock = mockFetch(200, { access_token: 'tok' })
    globalThis.fetch = fetchMock
    await api.auth.login('mykey')
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/auth/token')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ api_key: 'mykey' })
  })

  it('throws on 401', async () => {
    globalThis.fetch = mockFetch(401, { error: 'Unauthorized' })
    await expect(api.auth.login('bad-key')).rejects.toThrow()
  })
})

// ---------------------------------------------------------------------------
// organisations
// ---------------------------------------------------------------------------

describe('api.organisations.list', () => {
  beforeEach(() => localStorage.setItem(TOKEN_KEY, 'test-token'))

  it('calls /api/v1/organisations', async () => {
    const fetchMock = mockFetch(200, { data: [] })
    globalThis.fetch = fetchMock
    await api.organisations.list()
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/organisations')
  })

  it('includes Bearer auth header', async () => {
    const fetchMock = mockFetch(200, { data: [] })
    globalThis.fetch = fetchMock
    await api.organisations.list()
    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.headers.Authorization).toBe('Bearer test-token')
  })

  it('supports page and per_page params', async () => {
    const fetchMock = mockFetch(200, { data: [] })
    globalThis.fetch = fetchMock
    await api.organisations.list(2, 10)
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('page=2')
    expect(url).toContain('per_page=10')
  })

  it('returns the array from the response', async () => {
    const orgs = [{ id: 'o1', name: 'Acme' }]
    globalThis.fetch = mockFetch(200, { data: orgs })
    const result = await api.organisations.list()
    expect(result).toEqual(orgs)
  })
})

describe('api.organisations.get', () => {
  it('calls /organisations/:id', async () => {
    const fetchMock = mockFetch(200, { id: 'org-abc' })
    globalThis.fetch = fetchMock
    await api.organisations.get('org-abc')
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/organisations/org-abc')
  })
})

describe('api.organisations.create', () => {
  it('POSTs to /organisations', async () => {
    const fetchMock = mockFetch(201, { id: 'org-1', name: 'Acme' })
    globalThis.fetch = fetchMock
    const result = await api.organisations.create({
      name: 'Acme',
      country: 'DE',
      industry: 'Finance',
      size: 'medium',
      entity_type: 'essential',
    })
    expect(result.id).toBe('org-1')
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/organisations')
    expect(opts.method).toBe('POST')
  })
})

// ---------------------------------------------------------------------------
// assessments — orgId is a path segment, not a query param
// ---------------------------------------------------------------------------

describe('api.assessments.list', () => {
  it('builds path /organisations/:orgId/assessments', async () => {
    const fetchMock = mockFetch(200, [])
    globalThis.fetch = fetchMock
    await api.assessments.list('org-123')
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/organisations/org-123/assessments')
  })

  it('supports page and perPage params', async () => {
    const fetchMock = mockFetch(200, [])
    globalThis.fetch = fetchMock
    await api.assessments.list('org-1', 2, 25)
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('page=2')
    expect(url).toContain('per_page=25')
  })
})

describe('api.assessments.create', () => {
  it('POSTs to /organisations/:orgId/assessments', async () => {
    const fetchMock = mockFetch(201, { id: 'a-1' })
    globalThis.fetch = fetchMock
    await api.assessments.create('org-1', { title: 'Q1 2026', framework_version: '2.0' })
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/organisations/org-1/assessments')
    expect(opts.method).toBe('POST')
    const body = JSON.parse(opts.body)
    expect(body.title).toBe('Q1 2026')
  })
})

describe('api.assessments.get', () => {
  it('calls /assessments/:id', async () => {
    const fetchMock = mockFetch(200, { id: 'a-abc' })
    globalThis.fetch = fetchMock
    await api.assessments.get('a-abc')
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/a-abc')
  })
})

describe('api.assessments.patch', () => {
  it('sends PATCH to /assessments/:id', async () => {
    const fetchMock = mockFetch(200, { id: 'a-1', status: 'in_progress' })
    globalThis.fetch = fetchMock
    await api.assessments.patch('a-1', { status: 'in_progress' })
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/a-1')
    expect(opts.method).toBe('PATCH')
  })
})

// ---------------------------------------------------------------------------
// controls — list uses path, patch takes (assessmentId, measureRef, data)
// ---------------------------------------------------------------------------

describe('api.controls.list', () => {
  it('calls /assessments/:id/controls', async () => {
    const fetchMock = mockFetch(200, [])
    globalThis.fetch = fetchMock
    await api.controls.list('assess-1')
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/assess-1/controls')
  })
})

describe('api.controls.get', () => {
  it('calls /assessments/:id/controls/:measureRef', async () => {
    const fetchMock = mockFetch(200, { id: 'ctrl-a' })
    globalThis.fetch = fetchMock
    await api.controls.get('assess-1', 'a')
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/assess-1/controls/a')
  })
})

describe('api.controls.patch', () => {
  it('sends PATCH to /assessments/:id/controls/:measureRef', async () => {
    const fetchMock = mockFetch(200, { id: 'ctrl-a' })
    globalThis.fetch = fetchMock
    await api.controls.patch('assess-1', 'a', { status: 'compliant' })
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/assess-1/controls/a')
    expect(opts.method).toBe('PATCH')
    const body = JSON.parse(opts.body)
    expect(body.status).toBe('compliant')
  })
})

// ---------------------------------------------------------------------------
// reports.generate
// ---------------------------------------------------------------------------

describe('api.reports.generate', () => {
  it('POSTs to /assessments/:id/report', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      blob: () => Promise.resolve(new Blob(['pdf'], { type: 'application/pdf' })),
      json: () => Promise.resolve({}),
    })
    globalThis.fetch = fetchMock
    await api.reports.generate('assess-1')
    const [url, opts] = fetchMock.mock.calls[0]
    expect(url).toContain('/assessments/assess-1/report')
    expect(opts.method).toBe('POST')
  })

  it('returns a Blob', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers(),
      blob: () => Promise.resolve(new Blob(['data'])),
      json: () => Promise.resolve({}),
    })
    const result = await api.reports.generate('assess-1')
    expect(result instanceof Blob).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// audit.list
// ---------------------------------------------------------------------------

describe('api.audit.list', () => {
  it('reads X-Total-Count header', async () => {
    const entries = [{ id: 'e1', chain_hash: 'abc' }]
    globalThis.fetch = mockFetch(200, { data: entries }, { 'x-total-count': '55' })
    const result = await api.audit.list()
    expect(result.total).toBe(55)
    expect(result.entries).toEqual(entries)
  })

  it('filters by risk_class', async () => {
    const fetchMock = mockFetch(200, { data: [] }, { 'x-total-count': '0' })
    globalThis.fetch = fetchMock
    await api.audit.list({ risk_class: 'CRITICAL' })
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('risk_class=CRITICAL')
  })

  it('supports actor and action filters', async () => {
    const fetchMock = mockFetch(200, { data: [] }, { 'x-total-count': '0' })
    globalThis.fetch = fetchMock
    await api.audit.list({ actor: 'alice', action: 'assessment.created' })
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('actor=alice')
    expect(url).toContain('action=assessment.created')
  })
})

// ---------------------------------------------------------------------------
// 401 clears localStorage
// ---------------------------------------------------------------------------

describe('401 handling', () => {
  it('removes nis2compass_token from localStorage on 401', async () => {
    localStorage.setItem(TOKEN_KEY, 'stale')
    const reloadSpy = vi.fn()
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { reload: reloadSpy },
    })
    globalThis.fetch = mockFetch(401, { error: 'Unauthorized' })
    await expect(api.organisations.list()).rejects.toThrow()
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull()
  })
})
