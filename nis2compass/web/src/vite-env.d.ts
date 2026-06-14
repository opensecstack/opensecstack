/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SINAUTH_URL?: string
  readonly VITE_SINAUTH_SITE_URL?: string
  readonly VITE_SINAUTH_CLIENT_ID?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
