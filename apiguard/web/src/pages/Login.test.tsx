import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Login from './Login'

// Mock api module
vi.mock('../api', () => ({
  api: {
    auth: {
      login: vi.fn(),
    },
  },
}))

import { api } from '../api'

describe('Login page', () => {
  const onLogin = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the API key input and sign-in button', () => {
    render(<Login onLogin={onLogin} />)
    expect(screen.getByPlaceholderText(/api key/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('calls onLogin with the token on success', async () => {
    vi.mocked(api.auth.login).mockResolvedValueOnce('tok-xyz')
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByPlaceholderText(/api key/i), {
      target: { value: 'my-key' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(onLogin).toHaveBeenCalledWith('tok-xyz'))
  })

  it('stores the token in localStorage on success', async () => {
    vi.mocked(api.auth.login).mockResolvedValueOnce('tok-stored')
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByPlaceholderText(/api key/i), {
      target: { value: 'my-key' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() =>
      expect(localStorage.getItem('apiguard_token')).toBe('tok-stored'),
    )
  })

  it('shows an error message on failure', async () => {
    vi.mocked(api.auth.login).mockRejectedValueOnce(new Error('Invalid API key'))
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByPlaceholderText(/api key/i), {
      target: { value: 'bad-key' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByText(/invalid api key/i)).toBeInTheDocument())
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('disables the button while the request is in flight', async () => {
    let resolve!: (v: string) => void
    vi.mocked(api.auth.login).mockReturnValueOnce(
      new Promise<string>((r) => { resolve = r }),
    )
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByPlaceholderText(/api key/i), {
      target: { value: 'my-key' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    expect(screen.getByRole('button')).toBeDisabled()
    resolve('tok')
    await waitFor(() => expect(screen.getByRole('button')).not.toBeDisabled())
  })
})
