package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensecstack/community/internal/auth"
)

func TestIssue_ProducesVerifiableToken(t *testing.T) {
	signed, claims, err := auth.Issue("s3cret", "sin.to", "alice", "admin", time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if signed == "" {
		t.Fatal("expected non-empty signed token")
	}
	if claims.Sub != "alice" || claims.Role != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if claims.Issuer != "sin.to" {
		t.Errorf("expected issuer sin.to, got %q", claims.Issuer)
	}

	verified, err := auth.Verify(signed, "s3cret")
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if verified.Sub != "alice" || verified.Role != "admin" {
		t.Errorf("unexpected verified claims: %+v", verified)
	}
}

func TestVerify_WrongSecret_ReturnsErrInvalidToken(t *testing.T) {
	signed, _, err := auth.Issue("correct-secret", "sin.to", "bob", "viewer", time.Hour)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	_, err = auth.Verify(signed, "wrong-secret")
	if err != auth.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestVerify_ExpiredToken_ReturnsErrInvalidToken(t *testing.T) {
	signed, _, err := auth.Issue("s3cret", "sin.to", "carol", "author", -time.Hour)
	if err != nil {
		t.Fatalf("issue failed: %v", err)
	}

	_, err = auth.Verify(signed, "s3cret")
	if err != auth.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestVerify_MalformedToken_ReturnsErrInvalidToken(t *testing.T) {
	_, err := auth.Verify("not-a-jwt", "s3cret")
	if err != auth.ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

// TestVerify_RejectsAlgNone ensures the "alg: none" vulnerability is closed:
// a token signed with the "none" algorithm must never be accepted, since
// that would let an attacker forge arbitrary claims without knowing the secret.
func TestVerify_RejectsAlgNone(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, &auth.Claims{
		Sub:  "mallory",
		Role: "admin",
	})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to build alg:none token: %v", err)
	}

	_, err = auth.Verify(signed, "s3cret")
	if err != auth.ErrInvalidToken {
		t.Fatalf("expected alg:none token to be rejected, got %v", err)
	}
}

func TestHasRole(t *testing.T) {
	tests := []struct {
		role     string
		required string
		want     bool
	}{
		{"admin", "viewer", true},
		{"admin", "admin", true},
		{"moderator", "admin", false},
		{"viewer", "author", false},
		{"author", "author", true},
		{"", "viewer", false},
		// An unranked "required" role defaults to rank 0 in roleRank, so any
		// known role (rank >= 1) satisfies it. This documents the actual
		// (permissive) behavior of the zero-value map lookup.
		{"admin", "unknown-role", true},
		{"", "unknown-role", true},
	}
	for _, tt := range tests {
		if got := auth.HasRole(tt.role, tt.required); got != tt.want {
			t.Errorf("HasRole(%q, %q) = %v, want %v", tt.role, tt.required, got, tt.want)
		}
	}
}
