import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Login from './Login'

vi.mock('../sinauth', () => ({
  loginWithPopup: vi.fn(),
}))

import { loginWithPopup } from '../sinauth'

describe('Login page', () => {
  const onLogin = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('renders the sinauth sign-in button', () => {
    render(<Login onLogin={onLogin} />)
    expect(screen.getByRole('button', { name: /sign in with sinauth/i })).toBeInTheDocument()
  })

  it('calls onLogin with the access token on success', async () => {
    vi.mocked(loginWithPopup).mockResolvedValueOnce({
      access_token: 'tok-xyz',
      refresh_token: 'refresh-xyz',
      expires_in: 3600,
    })
    render(<Login onLogin={onLogin} />)

    fireEvent.click(screen.getByRole('button', { name: /sign in with sinauth/i }))

    await waitFor(() => expect(onLogin).toHaveBeenCalledWith('tok-xyz'))
  })

  it('stores the access token in localStorage on success', async () => {
    vi.mocked(loginWithPopup).mockResolvedValueOnce({
      access_token: 'tok-stored',
      refresh_token: 'refresh-stored',
      expires_in: 3600,
    })
    render(<Login onLogin={onLogin} />)

    fireEvent.click(screen.getByRole('button', { name: /sign in with sinauth/i }))

    await waitFor(() =>
      expect(localStorage.getItem('apiguard_token')).toBe('tok-stored'),
    )
  })

  it('shows an error message on failure', async () => {
    vi.mocked(loginWithPopup).mockRejectedValueOnce(new Error('Popup blocked. Please allow popups for this site.'))
    render(<Login onLogin={onLogin} />)

    fireEvent.click(screen.getByRole('button', { name: /sign in with sinauth/i }))

    await waitFor(() => expect(screen.getByText(/popup blocked/i)).toBeInTheDocument())
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('disables the button while the popup flow is in flight', async () => {
    let resolve!: (v: { access_token: string; refresh_token: string; expires_in: number }) => void
    vi.mocked(loginWithPopup).mockReturnValueOnce(
      new Promise((r) => { resolve = r }),
    )
    render(<Login onLogin={onLogin} />)

    fireEvent.click(screen.getByRole('button', { name: /sign in with sinauth/i }))

    expect(screen.getByRole('button')).toBeDisabled()
    resolve({ access_token: 'tok', refresh_token: 'refresh', expires_in: 3600 })
    await waitFor(() => expect(screen.getByRole('button')).not.toBeDisabled())
  })
})
