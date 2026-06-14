export interface SinauthClaims {
  sub: string
  client_id: string
  scope: string[]
  role: string
  client_roles: string[]
  iss: string
  aud: string[]
  exp: number
  iat: number
  jti: string
}

export interface UserInfo {
  sub: string
  email: string
  email_verified: boolean
  name: string
  picture?: string
}

export interface DiscoveryDocument {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  jwks_uri: string
  end_session_endpoint: string
  scopes_supported: string[]
  response_types_supported: string[]
  grant_types_supported: string[]
}

export interface TokenResponse {
  access_token: string
  id_token?: string
  refresh_token?: string
  token_type: string
  expires_in: number
  scope?: string
}

export interface PKCEParams {
  codeVerifier: string
  codeChallenge: string
  state: string
}
