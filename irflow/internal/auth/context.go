package auth

import "context"

// ctxKey is a private type to avoid collisions with other packages that
// store values on request context.
type ctxKey int

const (
	ctxKeyClaims ctxKey = iota
)

// WithClaims returns a new context carrying the provided claims.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, c)
}

// ClaimsFromContext extracts claims from ctx. Returns nil when no claims
// were set (e.g. the handler was reached with auth middleware disabled).
func ClaimsFromContext(ctx context.Context) *Claims {
	c, _ := ctx.Value(ctxKeyClaims).(*Claims)
	return c
}
