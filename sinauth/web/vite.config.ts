import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

// Proxy target for the sinauth API. Defaults to localhost for native dev;
// override with SINAUTH_API_PROXY (e.g. http://sinauth-api:8100) in containers.
const apiTarget = process.env.SINAUTH_API_PROXY || 'http://localhost:8100'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/api':             apiTarget,
      '/oauth/authorize': apiTarget,
      '/oauth/token':     apiTarget,
      '/oauth/userinfo':  apiTarget,
      '/oauth/callback':  apiTarget,
      '/admin':           apiTarget,
      '/federation':      apiTarget,
      '/.well-known':     apiTarget,
    },
  },
})
