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
    blob: () => Promise.resolve(new Blob([JSON.stringify(body)])),
  })
}

// ---------------------------------------------------------------------------
// auth.login
// ---------------------------------------------------------------------------

describe('api.auth.login', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('returns the token on success', async () => {
    globalThis.fetch = mockFetch(200, { token: 'tok-abc' })
    const token = await api.auth.login('my-api-key')
    expect(token).toBe('tok-abc')
  })

  it('throws on 401', async () => {
    globalThis.fetch = mockFetch(401, { error: 'Unauthorized' })
    await expect(api.auth.login('bad-key')).rejects.toThrow()
  })
})

// ---------------------------------------------------------------------------
// api.scans
// ---------------------------------------------------------------------------

describe('api.scans.list', () => {
  beforeEach(() => {
    localStorage.setItem('apiguard_token', 'test-token')
  })
  afterEach(() => {
    localStorage.clear()
  })

  it('calls the correct endpoint', async () => {
    const fetchMock = mockFetch(200, [])
    globalThis.fetch = fetchMock
    await api.scans.list(1, 10)
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/scans?page=1&per_page=10',
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: 'Bearer test-token' }),
      }),
    )
  })

  it('returns scan array', async () => {
    const scans = [{ id: 's1', status: 'completed', summary: {} }]
    globalThis.fetch = mockFetch(200, scans)
    const result = await api.scans.list()
    expect(result).toEqual(scans)
  })
})

describe('api.scans.get', () => {
  it('calls /scans/:id', async () => {
    const fetchMock = mockFetch(200, { id: 'abc' })
    globalThis.fetch = fetchMock
    await api.scans.get('abc')
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/scans/abc', expect.any(Object))
  })
})

describe('api.scans.create', () => {
  it('POSTs to /scans', async () => {
    const fetchMock = mockFetch(201, { id: 'new-scan', status: 'pending' })
    globalThis.fetch = fetchMock
    const result = await api.scans.create({ target: 'https://api.example.com' })
    expect(result.id).toBe('new-scan')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/scans',
      expect.objectContaining({ method: 'POST' }),
    )
  })
})

// ---------------------------------------------------------------------------
// api.findings
// ---------------------------------------------------------------------------

describe('api.findings.list', () => {
  it('builds query string correctly', async () => {
    const fetchMock = mockFetch(200, [])
    globalThis.fetch = fetchMock
    await api.findings.list({ severity: 'critical', status: 'open', page: 2 })
    const [url] = fetchMock.mock.calls[0]
    expect(url).toContain('severity=critical')
    expect(url).toContain('status=open')
    expect(url).toContain('page=2')
  })
})

describe('api.findings.updateStatus', () => {
  it('sends PATCH with status body', async () => {
    const fetchMock = mockFetch(200, { id: 'f1', status: 'confirmed' })
    globalThis.fetch = fetchMock
    await api.findings.updateStatus('f1', 'confirmed')
    const [, opts] = fetchMock.mock.calls[0]
    expect(opts.method).toBe('PATCH')
    expect(JSON.parse(opts.body)).toEqual({ status: 'confirmed' })
  })
})

// ---------------------------------------------------------------------------
// api.health
// ---------------------------------------------------------------------------

describe('api.health', () => {
  it('returns status and version', async () => {
    globalThis.fetch = mockFetch(200, { status: 'ok', version: '0.2.0' })
    const h = await api.health()
    expect(h.status).toBe('ok')
    expect(h.version).toBe('0.2.0')
  })
})

// ---------------------------------------------------------------------------
// api.audit.list
// ---------------------------------------------------------------------------

describe('api.audit.list', () => {
  it('reads X-Total-Count header', async () => {
    const entries = [{ id: 'e1' }]
    globalThis.fetch = mockFetch(200, entries, { 'x-total-count': '42' })
    const result = await api.audit.list({ page: 1 })
    expect(result.total).toBe(42)
    expect(result.entries).toEqual(entries)
  })
})

// ---------------------------------------------------------------------------
// Error handling: 401 triggers reload
// ---------------------------------------------------------------------------

describe('401 handling', () => {
  it('removes token from localStorage on 401', async () => {
    localStorage.setItem('apiguard_token', 'stale-token')
    // Intercept window.location.reload
    const reloadSpy = vi.fn()
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { reload: reloadSpy },
    })
    globalThis.fetch = mockFetch(401, { error: 'Unauthorized' })
    await expect(api.scans.list()).rejects.toThrow()
    expect(localStorage.getItem('apiguard_token')).toBeNull()
  })
})
