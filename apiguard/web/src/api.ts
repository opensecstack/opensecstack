import type { Scan, Finding, FindingStatus, AuditEntry } from './types'

const BASE = '/api/v1'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem('apiguard_token')
  const res = await fetch(BASE + path, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  })
  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem('apiguard_token')
      window.location.reload()
    }
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? res.statusText)
  }
  return res.json()
}

export const api = {
  auth: {
    login: async (apiKey: string): Promise<string> => {
      const res = await fetch(`${BASE}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: apiKey }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }))
        throw new Error(err.error ?? res.statusText)
      }
      const data: { token: string } = await res.json()
      return data.token
    },
  },
  scans: {
    list: (page = 1, perPage = 20) =>
      request<Scan[]>(`/scans?page=${page}&per_page=${perPage}`),
    get: (id: string) => request<Scan>(`/scans/${id}`),
    findings: (id: string, page = 1) =>
      request<Finding[]>(`/scans/${id}/findings?page=${page}`),
    create: (body: { spec_url?: string; spec_path?: string; target: string; modules?: string[] }) =>
      request<{ id: string; status: string }>('/scans', { method: 'POST', body: JSON.stringify(body) }),
    delete: (id: string) => request<void>(`/scans/${id}`, { method: 'DELETE' }),
  },
  findings: {
    list: (params?: { scan_id?: string; severity?: string; status?: string; page?: number }) => {
      const q = new URLSearchParams()
      if (params?.scan_id) q.set('scan_id', params.scan_id)
      if (params?.severity) q.set('severity', params.severity)
      if (params?.status) q.set('status', params.status)
      if (params?.page) q.set('page', String(params.page))
      return request<Finding[]>(`/findings?${q}`)
    },
    get: (id: string) => request<Finding>(`/findings/${id}`),
    updateStatus: (id: string, status: FindingStatus) =>
      request<Finding>(`/findings/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  },
  health: () => request<{ status: string; version: string }>('/health'),
  audit: {
    list: async (params?: { page?: number; per_page?: number; actor_id?: string; action?: string; resource_type?: string }) => {
      const q = new URLSearchParams()
      if (params?.page) q.set('page', String(params.page))
      if (params?.per_page) q.set('per_page', String(params.per_page))
      if (params?.actor_id) q.set('actor_id', params.actor_id)
      if (params?.action) q.set('action', params.action)
      if (params?.resource_type) q.set('resource_type', params.resource_type)
      const token = localStorage.getItem('apiguard_token')
      const res = await fetch(`${BASE}/audit?${q}`, {
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      })
      if (!res.ok) {
        if (res.status === 401) {
          localStorage.removeItem('apiguard_token')
          window.location.reload()
        }
        const err = await res.json().catch(() => ({ error: res.statusText }))
        throw new Error(err.error ?? res.statusText)
      }
      const total = parseInt(res.headers.get('X-Total-Count') ?? '0', 10)
      const entries: AuditEntry[] = await res.json()
      return { entries, total }
    },
  },
  specs: {
    upload: async (file: File): Promise<{ spec_path: string; spec_hash: string; size: number }> => {
      const token = localStorage.getItem('apiguard_token')
      const form = new FormData()
      form.append('spec', file)
      const res = await fetch(`${BASE}/specs/upload`, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
        body: form,
      })
      if (!res.ok) {
        if (res.status === 401) {
          localStorage.removeItem('apiguard_token')
          window.location.reload()
        }
        const err = await res.json().catch(() => ({ error: res.statusText }))
        throw new Error(err.error ?? res.statusText)
      }
      return res.json()
    },
  },
}
