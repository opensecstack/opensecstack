//go:build integration

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/token"
)

// testRSAKey generates a throwaway RSA key for building a token.Issuer in
// tests, mirroring internal/api/middleware/auth_test.go's pattern.
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// withClaimsSub attaches AccessTokenClaims (identified only by subject) to
// the request context the way middleware.BearerAuth does, so handlers gated
// by claimsUserID (webauthn.go) can be exercised directly without standing
// up the full HTTP auth middleware chain. See userinfo_test.go's withClaims
// for the sibling helper that takes a full claims struct.
func withClaimsSub(r *http.Request, sub string) *http.Request {
	claims := &token.AccessTokenClaims{Sub: sub}
	return r.WithContext(context.WithValue(r.Context(), middleware.ClaimsKey, claims))
}

// fakeSMSProvider is an in-memory mfa.SMSProvider for tests: it records sent
// messages and can be configured to fail, without touching the network.
type fakeSMSProvider struct {
	fail     bool
	sentTo   []string
	sentBody []string
}

func (f *fakeSMSProvider) Send(_ context.Context, to, body string) error {
	if f.fail {
		return context.DeadlineExceeded
	}
	f.sentTo = append(f.sentTo, to)
	f.sentBody = append(f.sentBody, body)
	return nil
}
