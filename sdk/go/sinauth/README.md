# sinauth Go SDK

Go SDK for verifying sinauth RS256 JWT tokens and integrating with the sinauth OIDC provider.

## Installation

```bash
go get github.com/opensecstack/sdk/go/sinauth
```

## Quick Start

```go
import "github.com/opensecstack/sdk/go/sinauth"

// Create a client — fetches the discovery document once.
client, err := sinauth.New("https://auth.sin.to")
if err != nil {
    log.Fatal(err)
}

// Verify a token.
claims, err := client.VerifyToken(ctx, tokenString)
if err != nil {
    // token is invalid or expired
}
fmt.Println(claims.Sub)       // username
fmt.Println(claims.Role)      // user role
fmt.Println(claims.ClientID)  // issuing client
```

## HTTP Middleware

```go
mux := http.NewServeMux()
mux.Handle("/api/protected", sinauth.BearerAuth(client)(protectedHandler))
```

Inside a protected handler, retrieve claims from context:

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    claims := sinauth.ClaimsFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s", claims.Sub)
}
```

## Client Verification

To ensure a token was issued for a specific OAuth client:

```go
claims, err := client.VerifyTokenForClient(ctx, tokenString, "my-app-client-id")
```

## UserInfo

```go
info, err := client.FetchUserInfo(ctx, accessToken)
fmt.Println(info.Email, info.Name)
```

## JWKS Caching

The SDK caches public keys for 5 minutes. On cache miss or key-not-found, it re-fetches JWKS automatically. No manual cache management needed.

## Claims

| Field | Type | Description |
|---|---|---|
| `Sub` | string | Username (subject) |
| `ClientID` | string | OAuth client that issued the token |
| `Scopes` | []string | Granted OAuth scopes |
| `Role` | string | User role (`admin`, `user`, etc.) |
| `ClientRoles` | []string | Client-specific roles |
| `Issuer` | string | sinauth issuer URL |
| `Audience` | []string | Intended audience |
| `ExpiresAt` | int64 | Unix timestamp |

## Environment Variables (when used in platforms)

| Variable | Description | Default |
|---|---|---|
| `SINAUTH_URL` | sinauth issuer base URL | `http://localhost:8100` |
