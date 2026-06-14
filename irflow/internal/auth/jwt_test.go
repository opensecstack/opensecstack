package auth

import (
	"errors"
	"testing"
	"time"
)

const testSecret = "unit-test-secret"

func TestIssueAndVerify_RoundTrip(t *testing.T) {
	token, err := Issue(testSecret, Claims{
		Subject: "alice",
		Role:    RoleOperator,
		Email:   "alice@example.com",
		Issuer:  "irflow",
	}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims, err := Verify(testSecret, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice" || claims.Role != RoleOperator || claims.Email != "alice@example.com" {
		t.Errorf("claims mismatch: %+v", claims)
	}
	if claims.IssuedAt == 0 {
		t.Error("IssuedAt was not auto-populated")
	}
	if claims.ExpiresAt == 0 {
		t.Error("ExpiresAt was not auto-populated from ttl")
	}
}

func TestVerify_RejectsWrongSecret(t *testing.T) {
	token, _ := Issue(testSecret, Claims{Subject: "alice", Role: RoleOperator}, time.Hour)
	_, err := Verify("other-secret", token)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	// Issue a token that expired 1 second ago.
	past := time.Now().Add(-1 * time.Second).Unix()
	token, err := Issue(testSecret, Claims{
		Subject:   "alice",
		Role:      RoleOperator,
		ExpiresAt: past,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(testSecret, token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("err = %v, want ErrTokenExpired", err)
	}
}

func TestVerify_RejectsNotYetValid(t *testing.T) {
	future := time.Now().Add(1 * time.Hour).Unix()
	token, err := Issue(testSecret, Claims{
		Subject:   "alice",
		Role:      RoleOperator,
		NotBefore: future,
	}, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(testSecret, token)
	if !errors.Is(err, ErrTokenNotYetValid) {
		t.Fatalf("err = %v, want ErrTokenNotYetValid", err)
	}
}

func TestVerify_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"only-one-part",
		"two.parts",
		"four.parts.here.extra",
		"aaa.bbb.cc",
	}
	for _, tok := range cases {
		if _, err := Verify(testSecret, tok); err == nil {
			t.Errorf("Verify(%q) returned nil, want error", tok)
		}
	}
}

func TestVerify_RejectsUnsupportedAlg(t *testing.T) {
	// Hand-crafted token with alg=none.
	header := `{"alg":"none","typ":"JWT"}`
	payload := `{"sub":"alice","role":"operator"}`
	tok := b64url(header) + "." + b64url(payload) + "."
	_, err := Verify(testSecret, tok)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("err = %v, want ErrUnsupportedAlg", err)
	}
}

func TestIssue_RejectsEmptySecret(t *testing.T) {
	if _, err := Issue("", Claims{Subject: "x"}, time.Hour); !errors.Is(err, ErrMissingSecret) {
		t.Fatalf("err = %v, want ErrMissingSecret", err)
	}
}

func TestIsKnownRole(t *testing.T) {
	for _, r := range AllRoles() {
		if !IsKnownRole(r) {
			t.Errorf("%q should be known", r)
		}
	}
	if IsKnownRole("rootkit") {
		t.Error("unknown role accepted")
	}
}

func TestPermissionMatrix(t *testing.T) {
	cases := []struct {
		role   string
		read   bool
		write  bool
		delete bool
	}{
		{RoleAdmin, true, true, true},
		{RoleOperator, true, true, false},
		{RoleVerifier, true, false, false},
		{RoleViewer, true, false, false},
		{RoleService, true, true, false},
		{"rogue", false, false, false},
	}
	for _, c := range cases {
		if got := canRead(c.role); got != c.read {
			t.Errorf("canRead(%s) = %v, want %v", c.role, got, c.read)
		}
		if got := canWrite(c.role); got != c.write {
			t.Errorf("canWrite(%s) = %v, want %v", c.role, got, c.write)
		}
		if got := canDelete(c.role); got != c.delete {
			t.Errorf("canDelete(%s) = %v, want %v", c.role, got, c.delete)
		}
	}
}
