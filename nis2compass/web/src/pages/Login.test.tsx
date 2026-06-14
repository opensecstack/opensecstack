import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import Login from './Login'

vi.mock('../api', () => ({
  api: {
    auth: {
      login: vi.fn(),
    },
  },
}))

import { api } from '../api'

const TOKEN_KEY = 'nis2compass_token'

describe('Login page', () => {
  const onLogin = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
  })

  it('renders the API key input', () => {
    render(<Login onLogin={onLogin} />)
    expect(screen.getByLabelText(/api key/i)).toBeInTheDocument()
  })

  it('renders the sign-in button', () => {
    render(<Login onLogin={onLogin} />)
    expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument()
  })

  it('calls onLogin with the token on success', async () => {
    vi.mocked(api.auth.login).mockResolvedValueOnce('tok-nis2')
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByLabelText(/api key/i), { target: { value: 'nis2_apk_test' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(onLogin).toHaveBeenCalledWith('tok-nis2'))
  })

  it('stores token in localStorage on success', async () => {
    vi.mocked(api.auth.login).mockResolvedValueOnce('tok-stored')
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByLabelText(/api key/i), { target: { value: 'key' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(localStorage.getItem(TOKEN_KEY)).toBe('tok-stored'))
  })

  it('shows error message on failure', async () => {
    vi.mocked(api.auth.login).mockRejectedValueOnce(new Error('Invalid API key'))
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByLabelText(/api key/i), { target: { value: 'bad' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByText(/invalid api key/i)).toBeInTheDocument())
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('disables the button while loading', async () => {
    let resolve!: (v: string) => void
    vi.mocked(api.auth.login).mockReturnValueOnce(
      new Promise<string>(r => { resolve = r }),
    )
    render(<Login onLogin={onLogin} />)

    fireEvent.change(screen.getByLabelText(/api key/i), { target: { value: 'key' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await waitFor(() => expect(screen.getByRole('button')).toBeDisabled())
    resolve('tok')
    await waitFor(() => expect(screen.getByRole('button')).not.toBeDisabled())
  })

  it('button is disabled when API key input is empty', () => {
    render(<Login onLogin={onLogin} />)
    expect(screen.getByRole('button', { name: /sign in/i })).toBeDisabled()
  })

  it('button enables when API key is typed', () => {
    render(<Login onLogin={onLogin} />)
    fireEvent.change(screen.getByLabelText(/api key/i), { target: { value: 'nis2_apk_x' } })
    expect(screen.getByRole('button', { name: /sign in/i })).not.toBeDisabled()
  })
})
