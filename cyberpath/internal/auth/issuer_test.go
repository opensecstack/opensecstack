package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer(IssuerConfig{
		SigningKey: []byte("test-signing-key"),
		Issuer:     "cyberpath-test",
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func TestNewIssuer_RejectsEmptyKey(t *testing.T) {
	_, err := NewIssuer(IssuerConfig{Issuer: "x"})
	if err == nil {
		t.Fatalf("NewIssuer: want error for empty signing key")
	}
}

func TestNewIssuer_DefaultsTTLs(t *testing.T) {
	iss, err := NewIssuer(IssuerConfig{SigningKey: []byte("k")})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	if iss.AccessTTL() != 8*time.Hour {
		t.Fatalf("AccessTTL default: got %v, want 8h", iss.AccessTTL())
	}
	if iss.RefreshTTL() != 7*24*time.Hour {
		t.Fatalf("RefreshTTL default: got %v, want 168h", iss.RefreshTTL())
	}
}

func TestIssueAccessToken_ContainsExpectedClaims(t *testing.T) {
	iss := testIssuer(t)
	tok, jti, err := iss.IssueAccessToken("user-1", RoleAdmin, "tenant-1")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if tok == "" || jti == "" {
		t.Fatalf("IssueAccessToken: got empty token/jti")
	}

	parsed, err := jwt.Parse(tok, func(*jwt.Token) (interface{}, error) {
		return []byte("test-signing-key"), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("re-parse of issued access token failed: %v", err)
	}
	mc := parsed.Claims.(jwt.MapClaims)
	if mc["sub"] != "user-1" {
		t.Fatalf("sub claim: got %v, want user-1", mc["sub"])
	}
	if mc["role"] != RoleAdmin {
		t.Fatalf("role claim: got %v, want %v", mc["role"], RoleAdmin)
	}
	if mc["tenant_id"] != "tenant-1" {
		t.Fatalf("tenant_id claim: got %v, want tenant-1", mc["tenant_id"])
	}
	if mc["typ"] != TokenTypeAccess {
		t.Fatalf("typ claim: got %v, want %v", mc["typ"], TokenTypeAccess)
	}
	if mc["jti"] != jti {
		t.Fatalf("jti claim mismatch: token has %v, returned %v", mc["jti"], jti)
	}
}

func TestIssueAccessToken_SetsAudienceWhenConfigured(t *testing.T) {
	iss, err := NewIssuer(IssuerConfig{
		SigningKey: []byte("k"),
		Issuer:     "iss",
		Audience:   "aud-1",
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, _, err := iss.IssueAccessToken("u", RoleLearner, "")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	parsed, err := jwt.Parse(tok, func(*jwt.Token) (interface{}, error) { return []byte("k"), nil })
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	mc := parsed.Claims.(jwt.MapClaims)
	if mc["aud"] != "aud-1" {
		t.Fatalf("aud claim: got %v, want aud-1", mc["aud"])
	}
}

func TestIssueRefreshAndParseRefresh_RoundTrip(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.IssueRefreshToken("user-1", "sess-1")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	sub, sid, jti, err := iss.ParseRefresh(tok)
	if err != nil {
		t.Fatalf("ParseRefresh: %v", err)
	}
	if sub != "user-1" || sid != "sess-1" || jti == "" {
		t.Fatalf("ParseRefresh: got sub=%q sid=%q jti=%q", sub, sid, jti)
	}
}

func TestParseRefresh_RejectsAccessToken(t *testing.T) {
	iss := testIssuer(t)
	accessTok, _, err := iss.IssueAccessToken("user-1", RoleAdmin, "")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if _, _, _, err := iss.ParseRefresh(accessTok); err == nil {
		t.Fatalf("ParseRefresh: want error when given an access token (typ=access)")
	}
}

func TestParseRefresh_RejectsIssuerMismatch(t *testing.T) {
	key := []byte("shared-key")
	issA, err := NewIssuer(IssuerConfig{SigningKey: key, Issuer: "issuer-a"})
	if err != nil {
		t.Fatalf("NewIssuer A: %v", err)
	}
	issB, err := NewIssuer(IssuerConfig{SigningKey: key, Issuer: "issuer-b"})
	if err != nil {
		t.Fatalf("NewIssuer B: %v", err)
	}
	tok, err := issA.IssueRefreshToken("u", "s")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	if _, _, _, err := issB.ParseRefresh(tok); err == nil {
		t.Fatalf("ParseRefresh: want issuer mismatch error")
	}
}

func TestParseRefresh_RejectsWrongSigningKey(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.IssueRefreshToken("u", "s")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	other, err := NewIssuer(IssuerConfig{SigningKey: []byte("different-key"), Issuer: "cyberpath-test"})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	if _, _, _, err := other.ParseRefresh(tok); err == nil {
		t.Fatalf("ParseRefresh: want error for wrong signing key")
	}
}

func TestParseRefresh_RejectsGarbage(t *testing.T) {
	iss := testIssuer(t)
	if _, _, _, err := iss.ParseRefresh("not-a-jwt"); err == nil {
		t.Fatalf("ParseRefresh: want error for malformed token")
	}
}

func TestParseRefresh_RejectsExpiredToken(t *testing.T) {
	iss, err := NewIssuer(IssuerConfig{
		SigningKey: []byte("k"),
		Issuer:     "iss",
		RefreshTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	iss.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tok, err := iss.IssueRefreshToken("u", "s")
	if err != nil {
		t.Fatalf("IssueRefreshToken: %v", err)
	}
	iss.now = time.Now
	if _, _, _, err := iss.ParseRefresh(tok); err == nil {
		t.Fatalf("ParseRefresh: want error for expired refresh token")
	}
}
