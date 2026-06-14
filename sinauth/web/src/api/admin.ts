import { api } from './client'

// Users
export const listUsers = (page = 1) =>
  api.get('/admin/users', { params: { page } }).then(r => r.data)
export const deactivateUser = (id: string) =>
  api.post(`/admin/users/${id}/deactivate`).then(r => r.data)

// Clients (OAuth applications)
export const listClients = () =>
  api.get('/admin/clients').then(r => r.data)
export const createClient = (data: Record<string, unknown>) =>
  api.post('/admin/clients', data).then(r => r.data)
export const deleteClient = (id: string) =>
  api.delete(`/admin/clients/${id}`).then(r => r.data)

// Groups (RBAC)
export const listGroups = () =>
  api.get('/admin/rbac/groups').then(r => r.data)
export const createGroup = (name: string, description: string) =>
  api.post('/admin/rbac/groups', { name, description }).then(r => r.data)
export const deleteGroup = (id: string) =>
  api.delete(`/admin/rbac/groups/${id}`).then(r => r.data)
export const listGroupMembers = (id: string) =>
  api.get(`/admin/rbac/groups/${id}/members`).then(r => r.data)
export const addGroupMember = (groupId: string, userId: string) =>
  api.post(`/admin/rbac/groups/${groupId}/members`, { user_id: userId }).then(r => r.data)

// Identity Providers
export const listProviders = () =>
  api.get('/api/v1/federation/providers').then(r => r.data)
export const createProvider = (data: Record<string, unknown>) =>
  api.post('/admin/federation/providers', data).then(r => r.data)
export const deleteProvider = (id: string) =>
  api.delete(`/admin/federation/providers/${id}`).then(r => r.data)

// Policies
export const listPolicies = () =>
  api.get('/admin/rbac/policies').then(r => r.data)
export const createPolicy = (data: Record<string, unknown>) =>
  api.post('/admin/rbac/policies', data).then(r => r.data)
export const deletePolicy = (id: string) =>
  api.delete(`/admin/rbac/policies/${id}`).then(r => r.data)
