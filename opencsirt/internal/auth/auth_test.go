package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func devAuth(t *testing.T) *Authenticator {
	t.Helper()
	pepper := "test-pepper"
	pwHash := sha256.Sum256([]byte(pepper + ":" + "secret"))
	users := "alice:admin:" + hex.EncodeToString(pwHash[:]) +
		",bob:viewer:" + hex.EncodeToString(pwHash[:])
	a, err := New([][]byte{[]byte(strings.Repeat("k", 32))}, "test", time.Hour, pepper, users)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestLoginIssuesValidToken(t *testing.T) {
	a := devAuth(t)
	tok, claims, err := a.Login("alice", "secret")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if claims.Role != RoleAdmin {
		t.Fatalf("role: got %v want admin", claims.Role)
	}
	got, err := a.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Sub != claims.Sub {
		t.Fatalf("sub mismatch")
	}
}

func TestLoginRejectsBadPassword(t *testing.T) {
	a := devAuth(t)
	if _, _, err := a.Login("alice", "wrong"); err != ErrInvalidCreds {
		t.Fatalf("got %v want ErrInvalidCreds", err)
	}
}

func TestRoleAtLeast(t *testing.T) {
	if !RoleAdmin.AtLeast(RoleAnalyst) {
		t.Fatal("admin must be ≥ analyst")
	}
	if RoleViewer.AtLeast(RoleAnalyst) {
		t.Fatal("viewer must NOT be ≥ analyst")
	}
	if !RoleExternalPeer.AtLeast(RoleViewer) {
		t.Fatal("external_peer must be ≥ viewer")
	}
	if RoleExternalPeer.AtLeast(RoleAnalyst) {
		t.Fatal("external_peer must NOT be ≥ analyst")
	}
}

func TestIssuerDisabledWhenNoUsers(t *testing.T) {
	a, err := New([][]byte{[]byte(strings.Repeat("k", 32))}, "test", time.Hour, "p", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, _, err := a.Login("nobody", "x"); err != ErrIssuerDisabled {
		t.Fatalf("got %v want ErrIssuerDisabled", err)
	}
}

func TestLoadUsersRejectsBadHex(t *testing.T) {
	_, err := New([][]byte{[]byte(strings.Repeat("k", 32))}, "test", time.Hour, "p",
		"alice:admin:zzzz")
	if err == nil {
		t.Fatal("expected error for bad hex")
	}
}
