package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
)

// ---------------------------------------------------------------------------
// validAPIKey — DB-less (static config key) path
// ---------------------------------------------------------------------------

func TestValidAPIKey_MatchesStaticKey(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("secret", "key-a", "key-b"))
	if !h.validAPIKey("key-a") {
		t.Error("expected key-a to be valid")
	}
	if !h.validAPIKey("key-b") {
		t.Error("expected key-b to be valid")
	}
}

func TestValidAPIKey_RejectsUnknownKey(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("secret", "key-a"))
	if h.validAPIKey("key-c") {
		t.Error("expected unknown key to be rejected")
	}
}

func TestValidAPIKey_EmptyKeyListRejectsEverything(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("secret"))
	if h.validAPIKey("anything") {
		t.Error("expected rejection when no static keys configured")
	}
	if h.validAPIKey("") {
		t.Error("expected empty key to be rejected")
	}
}

// ---------------------------------------------------------------------------
// issueJWT / validateRefreshToken round trip
// ---------------------------------------------------------------------------

func TestIssueJWTAndValidateRefreshToken_RoundTrip(t *testing.T) {
	tok, err := issueJWT("supersecret", "user-1", "apiguard", "apiguard", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}
	claims, err := validateRefreshToken(tok, "supersecret")
	if err != nil {
		t.Fatalf("validateRefreshToken: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("expected sub=user-1, got %q", claims.Sub)
	}
	if claims.Typ != "refresh" {
		t.Errorf("expected typ=refresh, got %q", claims.Typ)
	}
}

func TestValidateRefreshToken_MalformedSegments(t *testing.T) {
	_, err := validateRefreshToken("only.two", "secret")
	if err == nil {
		t.Fatal("expected error for token with 2 segments")
	}
}

func TestValidateRefreshToken_WrongSecret(t *testing.T) {
	tok, _ := issueJWT("secret-a", "user-1", "apiguard", "apiguard", "refresh", time.Hour)
	_, err := validateRefreshToken(tok, "secret-b")
	if err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestValidateRefreshToken_Expired(t *testing.T) {
	tok, _ := issueJWT("secret", "user-1", "apiguard", "apiguard", "refresh", -time.Hour)
	_, err := validateRefreshToken(tok, "secret")
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestValidateRefreshToken_WrongIssuer(t *testing.T) {
	tok, _ := issueJWT("secret", "user-1", "not-apiguard", "apiguard", "refresh", time.Hour)
	_, err := validateRefreshToken(tok, "secret")
	if err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestValidateRefreshToken_WrongAudience(t *testing.T) {
	tok, _ := issueJWT("secret", "user-1", "apiguard", "not-apiguard", "refresh", time.Hour)
	_, err := validateRefreshToken(tok, "secret")
	if err == nil {
		t.Fatal("expected audience mismatch error")
	}
}

func TestValidateRefreshToken_WrongTokenType(t *testing.T) {
	// An access token must not be usable as a refresh token.
	tok, _ := issueJWT("secret", "user-1", "apiguard", "apiguard", "access", time.Hour)
	_, err := validateRefreshToken(tok, "secret")
	if err == nil {
		t.Fatal("expected type mismatch error when presenting an access token as refresh")
	}
}

func TestValidateRefreshToken_MissingSub(t *testing.T) {
	tok, _ := issueJWT("secret", "", "apiguard", "apiguard", "refresh", time.Hour)
	_, err := validateRefreshToken(tok, "secret")
	if err == nil {
		t.Fatal("expected missing-sub error")
	}
}

func TestValidateRefreshToken_InvalidSignatureEncoding(t *testing.T) {
	tok, _ := issueJWT("secret", "user-1", "apiguard", "apiguard", "refresh", time.Hour)
	parts := splitToken(tok)
	bad := parts[0] + "." + parts[1] + ".not!base64!"
	_, err := validateRefreshToken(bad, "secret")
	if err == nil {
		t.Fatal("expected invalid signature encoding error")
	}
}

func splitToken(tok string) []string {
	var out []string
	start := 0
	for i, c := range tok {
		if c == '.' {
			out = append(out, tok[start:i])
			start = i + 1
		}
	}
	out = append(out, tok[start:])
	return out
}

// ---------------------------------------------------------------------------
// refreshTokenHash
// ---------------------------------------------------------------------------

func TestRefreshTokenHash_DeterministicAndDistinct(t *testing.T) {
	h1 := refreshTokenHash("token-a")
	h2 := refreshTokenHash("token-a")
	h3 := refreshTokenHash("token-b")
	if h1 != h2 {
		t.Errorf("expected same hash for same input, got %q vs %q", h1, h2)
	}
	if h1 == h3 {
		t.Error("expected different hashes for different inputs")
	}
	if len(h1) != 64 { // hex-encoded SHA-256 = 32 bytes = 64 hex chars
		t.Errorf("expected 64-char hex hash, got length %d", len(h1))
	}
}

// ---------------------------------------------------------------------------
// jwtBase64Decode
// ---------------------------------------------------------------------------

func TestJWTBase64Decode_ValidAndInvalid(t *testing.T) {
	encoded := jwtBase64([]byte("hello world"))
	decoded, err := jwtBase64Decode(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(decoded) != "hello world" {
		t.Errorf("expected 'hello world', got %q", decoded)
	}

	if _, err := jwtBase64Decode("not valid base64!!!"); err == nil {
		t.Fatal("expected error decoding invalid base64")
	}
}

// ---------------------------------------------------------------------------
// actorFromJWT
// ---------------------------------------------------------------------------

func TestActorFromJWT_WithClaims(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "alice"})
	req = req.WithContext(ctx)

	if got := actorFromJWT(req); got != "alice" {
		t.Errorf("expected alice, got %q", got)
	}
}

func TestActorFromJWT_NoClaims(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	if got := actorFromJWT(req); got != "unknown" {
		t.Errorf("expected unknown, got %q", got)
	}
}

func TestActorFromJWT_EmptySub(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: ""})
	req = req.WithContext(ctx)
	if got := actorFromJWT(req); got != "unknown" {
		t.Errorf("expected unknown for empty sub, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// validateAccessToken (secret rotation fallback)
// ---------------------------------------------------------------------------

func TestValidateAccessToken_PrimarySecretSucceeds(t *testing.T) {
	tok, _ := issueJWT("primary", "user-1", "apiguard", "apiguard", "access", time.Hour)
	claims, err := validateAccessToken(tok, "primary", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("expected sub=user-1, got %q", claims.Sub)
	}
}

func TestValidateAccessToken_FallsBackToGracePeriodSecret(t *testing.T) {
	sp := middleware.NewSecretProvider("primary")
	sp.Rotate([]byte("new-primary")) // "primary" is now grace-period only

	tok, _ := issueJWT("primary", "user-1", "apiguard", "apiguard", "access", time.Hour)
	claims, err := validateAccessToken(tok, "new-primary", sp)
	if err != nil {
		t.Fatalf("expected fallback to old secret to succeed: %v", err)
	}
	if claims.Sub != "user-1" {
		t.Errorf("expected sub=user-1, got %q", claims.Sub)
	}
}

func TestValidateAccessToken_AllSecretsFail(t *testing.T) {
	tok, _ := issueJWT("attacker-secret", "user-1", "apiguard", "apiguard", "access", time.Hour)
	sp := middleware.NewSecretProvider("primary", "old-secret")
	_, err := validateAccessToken(tok, "primary", sp)
	if err == nil {
		t.Fatal("expected failure when token is signed by an untrusted secret")
	}
}

// ---------------------------------------------------------------------------
// RefreshToken handler (DB-less)
// ---------------------------------------------------------------------------

func newRefreshRequest(body string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/refresh", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestRefreshToken_ValidTokenIssuesNewPair(t *testing.T) {
	cfg := testConfig("supersecret")
	cfg.Auth.TokenExpiry = time.Hour
	h := NewAuth(zerolog.Nop(), cfg)

	refreshTok, _ := issueJWT("supersecret", "user-1", "apiguard", "apiguard", "refresh", time.Hour)
	req := newRefreshRequest(`{"refresh_token":"` + refreshTok + `"}`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var out refreshResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.AccessToken == "" || out.RefreshToken == "" {
		t.Fatal("expected non-empty access and refresh tokens")
	}
	// The new refresh token must itself validate and carry the same subject.
	newClaims, err := validateRefreshToken(out.RefreshToken, "supersecret")
	if err != nil {
		t.Fatalf("newly issued refresh token failed validation: %v", err)
	}
	if newClaims.Sub != "user-1" {
		t.Errorf("expected sub=user-1 on reissued refresh token, got %q", newClaims.Sub)
	}
	if out.TokenType != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %q", out.TokenType)
	}
	if out.ExpiresIn != int64(time.Hour.Seconds()) {
		t.Errorf("expected expires_in=%d, got %d", int64(time.Hour.Seconds()), out.ExpiresIn)
	}
}

func TestRefreshToken_MissingSecret503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig(""))
	req := newRefreshRequest(`{"refresh_token":"x"}`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Result().StatusCode)
	}
}

func TestRefreshToken_MalformedBody400(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := newRefreshRequest(`not json`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestRefreshToken_EmptyToken401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := newRefreshRequest(`{"refresh_token":""}`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestRefreshToken_InvalidToken401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := newRefreshRequest(`{"refresh_token":"garbage.not.valid"}`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestRefreshToken_AccessTokenRejected(t *testing.T) {
	// An access token (typ=access) must not work as a refresh token.
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	accessTok, _ := issueJWT("supersecret", "user-1", "apiguard", "apiguard", "access", time.Hour)
	req := newRefreshRequest(`{"refresh_token":"` + accessTok + `"}`)
	w := httptest.NewRecorder()
	h.RefreshToken(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 when presenting an access token as refresh, got %d", w.Result().StatusCode)
	}
}

// ---------------------------------------------------------------------------
// RevokeRefreshToken handler (DB-less; in-memory revocation cache only)
// ---------------------------------------------------------------------------

func TestRevokeRefreshToken_NoBearer401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/auth/refresh", nil)
	w := httptest.NewRecorder()
	h.RevokeRefreshToken(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestRevokeRefreshToken_InvalidToken401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer garbage.not.valid")
	w := httptest.NewRecorder()
	h.RevokeRefreshToken(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestRevokeRefreshToken_FirstRevokeThenIdempotent(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	tok, _ := issueJWT("supersecret", "user-rev-1", "apiguard", "apiguard", "refresh", time.Hour)

	req1 := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/auth/refresh", nil)
	req1.Header.Set("Authorization", "Bearer "+tok)
	w1 := httptest.NewRecorder()
	h.RevokeRefreshToken(w1, req1)
	if w1.Result().StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 on first revoke, got %d", w1.Result().StatusCode)
	}

	// Second revocation of the same token should be idempotent (200, not 204).
	req2 := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/auth/refresh", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	w2 := httptest.NewRecorder()
	h.RevokeRefreshToken(w2, req2)
	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on idempotent re-revoke, got %d", w2.Result().StatusCode)
	}

	// The revoked token must now be rejected by RefreshToken.
	req3 := newRefreshRequest(`{"refresh_token":"` + tok + `"}`)
	w3 := httptest.NewRecorder()
	h.RefreshToken(w3, req3)
	if w3.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected revoked token to be rejected by RefreshToken, got %d", w3.Result().StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Logout handler (DB-less, with in-memory denylist)
// ---------------------------------------------------------------------------

func TestLogout_ValidTokenAddsToDenylist(t *testing.T) {
	denylist := middleware.NewTokenDenylist()
	defer denylist.Stop()
	h := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), nil, nil, nil, denylist)

	tok, _ := issueJWT("supersecret", "user-1", "apiguard", "apiguard", "access", time.Hour)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.Logout(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
	if !denylist.IsDenied(middleware.HashToken(tok)) {
		t.Error("expected token hash to be present in denylist after logout")
	}
}

func TestLogout_MissingBearer401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/logout", nil)
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestLogout_InvalidToken401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestLogout_MissingJWTSecret503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig(""))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	h.Logout(w, req)
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Result().StatusCode)
	}
}

// ---------------------------------------------------------------------------
// RotateSecret handler
// ---------------------------------------------------------------------------

func TestRotateSecret_NoProviderConfigured503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/auth/rotate", bytes.NewBufferString(`{"new_secret":"01234567890123456789012345678901"}`))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Result().StatusCode)
	}
}

func TestRotateSecret_TooShortSecret422(t *testing.T) {
	sp := middleware.NewSecretProvider("original-secret-that-is-long-enough")
	h := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), nil, nil, sp, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/auth/rotate", bytes.NewBufferString(`{"new_secret":"tooshort"}`))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	if w.Result().StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", w.Result().StatusCode)
	}
}

func TestRotateSecret_MalformedBody400(t *testing.T) {
	sp := middleware.NewSecretProvider("original-secret-that-is-long-enough")
	h := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), nil, nil, sp, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/auth/rotate", bytes.NewBufferString(`not json`))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestRotateSecret_ValidRequestRotates(t *testing.T) {
	sp := middleware.NewSecretProvider("original-secret-that-is-long-enough")
	h := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), nil, nil, sp, nil)

	newSecret := "brand-new-secret-that-is-long-enough-too"
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/admin/auth/rotate", bytes.NewBufferString(`{"new_secret":"`+newSecret+`"}`))
	w := httptest.NewRecorder()
	h.RotateSecret(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Result().StatusCode)
	}
	if string(sp.Current()) != newSecret {
		t.Errorf("expected active secret to be rotated to new value")
	}

	var out map[string]interface{}
	if err := json.NewDecoder(w.Result().Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body, _ := json.Marshal(out); bytes.Contains(body, []byte(newSecret)) {
		t.Error("response must never echo the new secret back")
	}
}
