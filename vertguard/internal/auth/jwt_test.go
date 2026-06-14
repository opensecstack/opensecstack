package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// mintHS256 hand-rolls a token signed with the given secret. Mirrors
// the production code path in cmd/server and the integration helper.
func mintHS256(t *testing.T, secret, role, issuer string, ttl time.Duration) string {
	t.Helper()
	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	claims := map[string]any{
		"sub":  "test-user",
		"role": role,
		"iss":  issuer,
		"exp":  time.Now().Add(ttl).Unix(),
		"iat":  time.Now().Unix(),
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signed := enc(header) + "." + enc(claims)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// recordingMetrics captures IncSecretUsed calls for assertion.
type recordingMetrics struct {
	mu    sync.Mutex
	slots []string
}

func (r *recordingMetrics) IncSecretUsed(slot string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.slots = append(r.slots, slot)
}

func (r *recordingMetrics) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.slots))
	copy(out, r.slots)
	return out
}

const (
	tIssuer   = "vertguard-test"
	tPrimary  = "primary-secret-key-32-bytes-min-aaaaaaaaa"
	tNext     = "next-secret-key-32-bytes-minimum-bbbbbbbbb"
	tPrevious = "previous-secret-key-32-bytes-min-ccccccccc"
)

func TestVerifier_PrimarySecret(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary, tNext, tPrevious}, tIssuer)
	tok := mintHS256(t, tPrimary, RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("primary verify: %v", err)
	}
}

func TestVerifier_NextSecret(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary, tNext, tPrevious}, tIssuer)
	tok := mintHS256(t, tNext, RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("next verify: %v", err)
	}
}

func TestVerifier_PreviousSecret(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary, tNext, tPrevious}, tIssuer)
	tok := mintHS256(t, tPrevious, RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("previous verify: %v", err)
	}
}

func TestVerifier_UnknownSecret_Rejected(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary, tNext}, tIssuer)
	tok := mintHS256(t, "totally-different-secret-xxxxxxxxxxx", RoleOperator, tIssuer, time.Hour)
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrSignatureBad) {
		t.Fatalf("err = %v, want ErrSignatureBad", err)
	}
}

func TestVerifierMulti_AllEmpty_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on all-empty secrets")
		}
	}()
	_ = NewVerifierMulti([]string{"", "", ""}, tIssuer)
}

func TestVerifierMulti_FiltersEmptyStrings(t *testing.T) {
	// Empty middle slot must be filtered. Critically: a token with an
	// empty signature payload signed against the empty secret must NOT
	// validate, because the empty entry was removed before HMAC.
	v := NewVerifierMulti([]string{tPrimary, "", tPrevious}, tIssuer)
	if len(v.secrets) != 2 {
		t.Fatalf("secrets len = %d, want 2", len(v.secrets))
	}

	// Token signed with "" must NOT validate.
	tok := mintHS256(t, "", RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(tok); !errors.Is(err, ErrSignatureBad) {
		t.Fatalf("empty-secret token: err = %v, want ErrSignatureBad", err)
	}

	// Tokens signed with the surviving secrets still work, and the
	// previous slot keeps its name (it is in position 2 in input).
	prevTok := mintHS256(t, tPrevious, RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(prevTok); err != nil {
		t.Fatalf("previous after filter: %v", err)
	}
}

func TestVerifier_MetricsRecordSlot(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary, tNext, tPrevious}, tIssuer)
	rec := &recordingMetrics{}
	v.SetMetrics(rec)

	cases := []struct {
		secret   string
		wantSlot string
	}{
		{tPrimary, "primary"},
		{tNext, "next"},
		{tPrevious, "previous"},
	}
	for _, c := range cases {
		tok := mintHS256(t, c.secret, RoleOperator, tIssuer, time.Hour)
		if _, err := v.Verify(tok); err != nil {
			t.Fatalf("verify %s: %v", c.wantSlot, err)
		}
	}

	got := rec.snapshot()
	if len(got) != 3 {
		t.Fatalf("metric calls = %d, want 3 (got %v)", len(got), got)
	}
	for i, c := range cases {
		if got[i] != c.wantSlot {
			t.Errorf("call %d: slot=%q want %q", i, got[i], c.wantSlot)
		}
	}
}

func TestVerifier_MetricsNotIncrementedOnFailure(t *testing.T) {
	v := NewVerifierMulti([]string{tPrimary}, tIssuer)
	rec := &recordingMetrics{}
	v.SetMetrics(rec)

	tok := mintHS256(t, "wrong-secret", RoleOperator, tIssuer, time.Hour)
	if _, err := v.Verify(tok); !errors.Is(err, ErrSignatureBad) {
		t.Fatalf("err = %v, want ErrSignatureBad", err)
	}
	if len(rec.snapshot()) != 0 {
		t.Fatalf("metric incremented on failure: %v", rec.snapshot())
	}
}

func TestNewVerifier_BackwardsCompat(t *testing.T) {
	// Single-secret constructor must keep working unchanged.
	v := NewVerifier(tPrimary, tIssuer)
	tok := mintHS256(t, tPrimary, RoleOperator, tIssuer, time.Hour)
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Role != RoleOperator {
		t.Fatalf("role = %q", claims.Role)
	}
}
