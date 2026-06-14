package auth

import (
	"context"
	"testing"
	"time"
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
