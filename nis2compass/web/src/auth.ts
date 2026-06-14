import type { Role } from './types'

export const ROLE_HIERARCHY: Record<Role, number> = {
  viewer:   0,
  auditor:  1,
  assessor: 2,
  admin:    3,
}

export function hasRole(userRole: Role | undefined, required: Role): boolean {
  if (userRole === undefined) return false
  return ROLE_HIERARCHY[userRole] >= ROLE_HIERARCHY[required]
}

export function decodeTokenRole(token: string): Role | undefined {
  try {
    const payload = JSON.parse(
      atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')),
    )
    const role = payload.role
    if (role === 'viewer' || role === 'auditor' || role === 'assessor' || role === 'admin') {
      return role as Role
    }
    return undefined
  } catch {
    return undefined
  }
}

const TOKEN_KEY = 'nis2compass_token'
const ROLE_KEY = 'nis2compass_role'

export function saveAuth(token: string, role: Role): void {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(ROLE_KEY, role)
}

export function loadAuth(): { token: string; role: Role } | null {
  const token = localStorage.getItem(TOKEN_KEY)
  const role = localStorage.getItem(ROLE_KEY) as Role | null
  if (!token || !role) return null
  if (!(role in ROLE_HIERARCHY)) return null
  return { token, role }
}
