import type { Organisation, Assessment, Control, AuditEntry } from './types'

const BASE = '/api/v1'
const TOKEN_KEY = 'nis2compass_token'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const token = localStorage.getItem(TOKEN_KEY)
  const res = await fetch(BASE + path, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  })
  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      window.location.reload()
    }
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? res.statusText)
  }
  return res.json()
}

async function requestWithHeaders<T>(
  path: string,
  options?: RequestInit,
): Promise<{ data: T; headers: Headers }> {
  const token = localStorage.getItem(TOKEN_KEY)
  const res = await fetch(BASE + path, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...options,
  })
  if (!res.ok) {
    if (res.status === 401) {
      localStorage.removeItem(TOKEN_KEY)
      window.location.reload()
    }
    const err = await res.json().catch(() => ({ error: res.statusText }))
    throw new Error(err.error ?? res.statusText)
  }
  const data: T = await res.json()
  return { data, headers: res.headers }
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

  organisations: {
    list: (page = 1, perPage = 100) =>
      request<Organisation[]>(`/organisations?page=${page}&per_page=${perPage}`),
    get: (id: string) => request<Organisation>(`/organisations/${id}`),
    create: (data: {
      name: string
      industry: string
      country: string
      size: string
      entity_type: string
      registration_number?: string
      contact_email?: string
    }) =>
      request<Organisation>('/organisations', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
  },

  assessments: {
    list: (orgId: string, page = 1, perPage = 50) =>
      request<Assessment[]>(
        `/organisations/${orgId}/assessments?page=${page}&per_page=${perPage}`,
      ),
    get: (id: string) => request<Assessment>(`/assessments/${id}`),
    create: (
      orgId: string,
      data: {
        title: string
        framework_version?: string
        scope?: string
        assessor?: string
        due_date?: string
      },
    ) =>
      request<Assessment>(`/organisations/${orgId}/assessments`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    patch: (id: string, data: Partial<{ status: string; assessor: string; due_date: string; scope: string }>) =>
      request<Assessment>(`/assessments/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
  },

  controls: {
    list: (assessmentId: string) =>
      request<Control[]>(`/assessments/${assessmentId}/controls`),
    get: (assessmentId: string, measureRef: string) =>
      request<Control>(`/assessments/${assessmentId}/controls/${measureRef}`),
    patch: (
      assessmentId: string,
      measureRef: string,
      data: Partial<{
        status: string
        notes: string
        gap_description: string
        remediation_plan: string
        remediation_due: string
        risk_score: number
        evidence: Record<string, unknown>
      }>,
    ) =>
      request<Control>(`/assessments/${assessmentId}/controls/${measureRef}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
  },

  reports: {
    generate: async (assessmentId: string): Promise<Blob> => {
      const token = localStorage.getItem(TOKEN_KEY)
      const res = await fetch(`${BASE}/assessments/${assessmentId}/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      })
      if (!res.ok) {
        if (res.status === 401) {
          localStorage.removeItem(TOKEN_KEY)
          window.location.reload()
        }
        const err = await res.json().catch(() => ({ error: res.statusText }))
        throw new Error(err.error ?? res.statusText)
      }
      return res.blob()
    },
  },

  audit: {
    list: async (params?: {
      actor?: string
      action?: string
      resource_type?: string
      resource_id?: string
      risk_class?: string
      after?: string
      page?: number
      per_page?: number
    }): Promise<{ entries: AuditEntry[]; total: number }> => {
      const q = new URLSearchParams()
      if (params?.actor) q.set('actor', params.actor)
      if (params?.action) q.set('action', params.action)
      if (params?.resource_type) q.set('resource_type', params.resource_type)
      if (params?.resource_id) q.set('resource_id', params.resource_id)
      if (params?.risk_class) q.set('risk_class', params.risk_class)
      if (params?.after) q.set('after', params.after)
      if (params?.page) q.set('page', String(params.page))
      if (params?.per_page) q.set('per_page', String(params.per_page))
      const { data, headers } = await requestWithHeaders<AuditEntry[]>(`/audit?${q}`)
      const total = parseInt(headers.get('X-Total-Count') ?? '0', 10)
      return { entries: data, total }
    },
  },
}
