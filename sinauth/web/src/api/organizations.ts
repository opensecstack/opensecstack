import { api } from './client'

// Mirrors the Go struct returned by GET /api/v1/users/me/organizations
// (sinauth ADR 005 §3 — organization picker step).
export interface OrganizationMembership {
  organization_id: string
  org_role: 'owner' | 'admin' | 'member'
  org_type: 'government' | 'private' | 'ecommerce' | 'ngo'
  slug: string
  legal_name: string
}

// Requires the caller to already be authenticated (session cookie set by a
// prior /oauth/authorize submission, or the sinauth_token bearer header
// attached by the `api` client's interceptor — see api/client.ts).
export const listMyOrganizations = () =>
  api.get<OrganizationMembership[]>('/api/v1/users/me/organizations').then(r => r.data)
