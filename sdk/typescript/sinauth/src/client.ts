import { createRemoteJWKSet, jwtVerify } from 'jose'
import type { SinauthClaims, UserInfo, DiscoveryDocument, TokenResponse } from './types.js'

export class SinauthClient {
  private readonly issuer: string
  private discovery: DiscoveryDocument | null = null
  private jwks: ReturnType<typeof createRemoteJWKSet> | null = null

  constructor(issuerURL: string) {
    this.issuer = issuerURL.replace(/\/$/, '')
  }

  // Fetch and cache OIDC discovery document
  async getDiscovery(): Promise<DiscoveryDocument> {
    if (this.discovery) return this.discovery
    const res = await fetch(`${this.issuer}/.well-known/openid-configuration`)
    if (!res.ok) throw new Error(`sinauth: discovery failed: ${res.status}`)
    this.discovery = await res.json() as DiscoveryDocument
    return this.discovery
  }

  // Verify an access token, returning typed claims
  async verifyToken(tokenString: string): Promise<SinauthClaims> {
    const discovery = await this.getDiscovery()
    if (!this.jwks) {
      this.jwks = createRemoteJWKSet(new URL(discovery.jwks_uri))
    }
    const { payload } = await jwtVerify(tokenString, this.jwks, {
      issuer: this.issuer,
      algorithms: ['RS256'],
    })
    return payload as unknown as SinauthClaims
  }

  // Verify token AND check audience matches clientID
  async verifyTokenForClient(tokenString: string, clientID: string): Promise<SinauthClaims> {
    const claims = await this.verifyToken(tokenString)
    const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
    if (claims.client_id !== clientID && !aud.includes(clientID)) {
      throw new Error(`sinauth: token not issued for client "${clientID}"`)
    }
    return claims
  }

  // Fetch userinfo from sinauth
  async fetchUserInfo(accessToken: string): Promise<UserInfo> {
    const discovery = await this.getDiscovery()
    const res = await fetch(discovery.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!res.ok) throw new Error(`sinauth: userinfo failed: ${res.status}`)
    return res.json() as Promise<UserInfo>
  }

  // Exchange authorization code for tokens (server-side or Node.js)
  async exchangeCode(params: {
    code: string
    redirectUri: string
    clientID: string
    clientSecret?: string
    codeVerifier?: string
  }): Promise<TokenResponse> {
    const discovery = await this.getDiscovery()
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: params.redirectUri,
      client_id: params.clientID,
    })
    if (params.clientSecret) body.set('client_secret', params.clientSecret)
    if (params.codeVerifier) body.set('code_verifier', params.codeVerifier)

    const res = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({})) as Record<string, unknown>
      throw new Error(`sinauth: token exchange failed: ${err['error'] ?? res.status}`)
    }
    return res.json() as Promise<TokenResponse>
  }
}
