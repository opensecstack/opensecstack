package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestAtLeast(t *testing.T) {
	cases := []struct {
		have, required Role
		want           bool
	}{
		{RoleAdmin, RoleOperator, true},
		{RoleOperator, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{RoleAnalyst, RoleOperator, false},
		{RoleOperator, RoleAnalyst, true},
	}
	for _, c := range cases {
		if got := AtLeast(c.have, c.required); got != c.want {
			t.Errorf("AtLeast(%s, %s) = %v, want %v", c.have, c.required, got, c.want)
		}
	}
}

func TestIssueAndVerifyToken_RoundTrip(t *testing.T) {
	s, err := NewService(Config{Secret: "test-secret-at-least-32-chars-long", TTL: 5 * time.Minute})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	id := &Identity{Subject: "apikey:foo", Role: RoleOperator, Source: "api_key"}
	tok, exp, err := s.IssueToken(id)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("exp should be in the future")
	}
	got, err := s.VerifyToken(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != id.Subject || got.Role != id.Role {
		t.Errorf("mismatch: %+v vs %+v", got, id)
	}
}

func TestVerifyToken_RejectsExpired(t *testing.T) {
	s, _ := NewService(Config{Secret: "s-is-long-enough-for-hs256-test-x", TTL: 1 * time.Millisecond})
	tok, _, _ := s.IssueToken(&Identity{Subject: "x", Role: RoleViewer})
	time.Sleep(10 * time.Millisecond)
	if _, err := s.VerifyToken(tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyToken_RejectsBadSecret(t *testing.T) {
	a, _ := NewService(Config{Secret: "secret-a-padded-to-32-chars-xxxx", TTL: time.Minute})
	b, _ := NewService(Config{Secret: "secret-b-padded-to-32-chars-xxxx", TTL: time.Minute})
	tok, _, _ := a.IssueToken(&Identity{Subject: "x", Role: RoleViewer})
	if _, err := b.VerifyToken(tok); err == nil {
		t.Fatal("expected error verifying with different secret")
	}
}

func TestAuthenticateAPIKey_Bootstrap(t *testing.T) {
	s, _ := NewService(Config{
		Secret:        "long-enough-secret-for-hs256-x",
		BootstrapKeys: map[string]Role{"admin-bootstrap-key": RoleAdmin},
	})
	id, err := s.AuthenticateAPIKey(context.Background(), "admin-bootstrap-key")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id.Role != RoleAdmin || id.Source != "bootstrap" {
		t.Errorf("unexpected: %+v", id)
	}
}

func TestAuthenticateAPIKey_UnknownReturnsUnauthorized(t *testing.T) {
	s, _ := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})
	if _, err := s.AuthenticateAPIKey(context.Background(), "nope"); err == nil {
		t.Fatal("expected unauthorized")
	}
}

// TestAuthenticateAPIKey_EmptyStringReturnsUnauthorized proves the guard
// against an empty/whitespace-only key fires before any bootstrap or store
// lookup — an empty credential must never be treated as "unknown, fall
// through", it must fail fast.
func TestAuthenticateAPIKey_EmptyStringReturnsUnauthorized(t *testing.T) {
	s, _ := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})
	if _, err := s.AuthenticateAPIKey(context.Background(), "   "); err != ErrUnauthorized {
		t.Fatalf("AuthenticateAPIKey(whitespace) = %v, want ErrUnauthorized", err)
	}
	if _, err := s.AuthenticateAPIKey(context.Background(), ""); err != ErrUnauthorized {
		t.Fatalf("AuthenticateAPIKey(\"\") = %v, want ErrUnauthorized", err)
	}
}

// TestAuthenticateAPIKey_NoStoreConfiguredFailsClosed proves that when no
// api key store is wired (s.apiKeys == nil) and the key doesn't match a
// bootstrap entry, authentication fails closed with ErrUnauthorized rather
// than panicking on a nil store dereference or silently granting access.
func TestAuthenticateAPIKey_NoStoreConfiguredFailsClosed(t *testing.T) {
	s, _ := NewService(Config{
		Secret:        "long-enough-secret-for-hs256-x",
		BootstrapKeys: map[string]Role{"only-this-key": RoleAdmin},
	})
	_, err := s.AuthenticateAPIKey(context.Background(), "some-other-key-not-in-bootstrap")
	if err != ErrUnauthorized {
		t.Fatalf("AuthenticateAPIKey with nil store = %v, want ErrUnauthorized", err)
	}
}

// TestAuthenticateAPIKey_BootstrapSubjectTruncatedToEightChars pins the
// documented subject format: "bootstrap:" + first 8 chars of the key. This
// guards against ever leaking the full plaintext bootstrap credential into
// logs/audit records via the Subject field.
func TestAuthenticateAPIKey_BootstrapSubjectTruncatedToEightChars(t *testing.T) {
	s, _ := NewService(Config{
		Secret:        "long-enough-secret-for-hs256-x",
		BootstrapKeys: map[string]Role{"abcdefghijklmnop": RoleViewer},
	})
	id, err := s.AuthenticateAPIKey(context.Background(), "abcdefghijklmnop")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if want := "bootstrap:abcdefgh"; id.Subject != want {
		t.Fatalf("Subject = %q, want %q (must not leak full plaintext key)", id.Subject, want)
	}
}

// TestAuthenticateAPIKey_ShortBootstrapKeyDoesNotPanic proves the min()
// truncation guard handles bootstrap keys shorter than 8 chars without
// slicing out of bounds.
func TestAuthenticateAPIKey_ShortBootstrapKeyDoesNotPanic(t *testing.T) {
	s, _ := NewService(Config{
		Secret:        "long-enough-secret-for-hs256-x",
		BootstrapKeys: map[string]Role{"ab": RoleViewer},
	})
	id, err := s.AuthenticateAPIKey(context.Background(), "ab")
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if id.Subject != "bootstrap:ab" {
		t.Fatalf("Subject = %q, want %q", id.Subject, "bootstrap:ab")
	}
}

// TestNewService_EmptySecretGeneratesRandomSecret proves the documented
// "empty secret -> generate a random one" fallback actually produces a
// usable, non-empty secret capable of signing and verifying tokens (and
// that two independently-generated secrets differ, i.e. it isn't a fixed
// placeholder).
func TestNewService_EmptySecretGeneratesRandomSecret(t *testing.T) {
	a, err := NewService(Config{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	b, err := NewService(Config{})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	tok, _, err := a.IssueToken(&Identity{Subject: "x", Role: RoleViewer})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.VerifyToken(tok); err != nil {
		t.Fatalf("a should verify its own token: %v", err)
	}
	if _, err := b.VerifyToken(tok); err == nil {
		t.Fatal("b (independently generated secret) must not verify a's token")
	}
}

// TestNewService_DefaultTTLIsOneHour proves the documented default (ttl<=0
// -> 1h) is actually applied, and that TTL() reports it back correctly.
func TestNewService_DefaultTTLIsOneHour(t *testing.T) {
	s, err := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if got := s.TTL(); got != time.Hour {
		t.Fatalf("TTL() = %v, want 1h", got)
	}
}

// TestNewService_CustomTTLIsPreserved proves a positive TTL passed in Config
// is used verbatim rather than being overridden by the default.
func TestNewService_CustomTTLIsPreserved(t *testing.T) {
	s, err := NewService(Config{Secret: "long-enough-secret-for-hs256-x", TTL: 15 * time.Minute})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	if got := s.TTL(); got != 15*time.Minute {
		t.Fatalf("TTL() = %v, want 15m", got)
	}
}

// TestVerifyToken_RejectsAlgNoneAttack is a fail-closed security regression
// guard: a JWT with alg=none (or any non-HMAC algorithm) must be rejected
// outright. VerifyToken's key-func explicitly type-asserts
// *jwt.SigningMethodHMAC — this test proves that guard actually blocks the
// classic "alg confusion" forgery where an attacker crafts a token with
// alg=none and an empty signature, hoping a permissive verifier accepts it
// without ever checking the MAC.
func TestVerifyToken_RejectsAlgNoneAttack(t *testing.T) {
	s, _ := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})

	claims := jwt.MapClaims{
		"sub":  "apikey:attacker",
		"role": string(RoleAdmin),
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forged, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("build alg=none token: %v", err)
	}

	if _, err := s.VerifyToken(forged); err == nil {
		t.Fatal("VerifyToken accepted an alg=none forged token — signature verification was bypassed")
	}
}

// TestVerifyToken_RejectsMalformedString proves garbage input (not a JWT at
// all) returns ErrUnauthorized rather than panicking.
func TestVerifyToken_RejectsMalformedString(t *testing.T) {
	s, _ := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})
	if _, err := s.VerifyToken("not.a.jwt"); err != ErrUnauthorized {
		t.Fatalf("VerifyToken(garbage) = %v, want ErrUnauthorized", err)
	}
	if _, err := s.VerifyToken(""); err != ErrUnauthorized {
		t.Fatalf("VerifyToken(\"\") = %v, want ErrUnauthorized", err)
	}
}

// TestVerifyToken_PreservesAPIKeyID proves the "kid" claim round-trips back
// into Identity.APIKey — downstream code (e.g. TouchUsed-style bookkeeping)
// depends on this to identify which stored API key issued the token.
func TestVerifyToken_PreservesAPIKeyID(t *testing.T) {
	s, _ := NewService(Config{Secret: "long-enough-secret-for-hs256-x"})
	keyID := uuid.New()
	id := &Identity{Subject: "apikey:" + keyID.String(), Role: RoleOperator, Source: "api_key", APIKey: &keyID}
	tok, _, err := s.IssueToken(id)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.VerifyToken(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.APIKey == nil {
		t.Fatal("expected APIKey to round-trip through kid claim")
	}
	if *got.APIKey != keyID {
		t.Errorf("APIKey = %s, want %s", got.APIKey, keyID)
	}
}

// TestAtLeast_UnknownRoleReturnsFalse proves an unrecognised role string
// (not one of the four canonical roles) is treated as insufficient
// privilege rather than accidentally satisfying every requirement via a
// zero-value map lookup. This is a fail-closed authorization guard.
func TestAtLeast_UnknownRoleReturnsFalse(t *testing.T) {
	if AtLeast(Role("bogus"), RoleViewer) {
		t.Fatal("unknown 'have' role must not satisfy any requirement")
	}
	if AtLeast(RoleAdmin, Role("bogus")) {
		t.Fatal("unknown 'required' role must never be satisfiable")
	}
}
