import axios from 'axios'

export const api = axios.create({ baseURL: '/' })

api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('sinauth_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) {
      localStorage.removeItem('sinauth_token')
      window.location.href = '/login'
    }
    return Promise.reject(err)
  }
)
