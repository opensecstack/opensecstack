//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/email"
	"github.com/opensecstack/sinauth/internal/token"
)

func doVerifyEmailRequest(t *testing.T, d Deps, token string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/api/v1/auth/verify-email"
	if token != "" {
		url += "?token=" + token
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	VerifyEmail(d)(rec, req)
	return rec
}

// TestVerifyEmail_MissingToken_BadRequest proves the required query
// parameter is enforced.
func TestVerifyEmail_MissingToken_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})

	rec := doVerifyEmailRequest(t, d, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestVerifyEmail_InvalidToken_BadRequest proves a token that was never
// issued (or already consumed) is rejected, not silently treated as valid.
func TestVerifyEmail_InvalidToken_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})

	rec := doVerifyEmailRequest(t, d, fmt.Sprintf("bogus-token-%d", time.Now().UnixNano()))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestVerifyEmail_ValidToken_MarksVerifiedAndConsumesToken proves the happy
// path both responds 200 and durably flips users.email_verified — and that
// the token is single-use (RFC-style consume semantics), not replayable.
func TestVerifyEmail_ValidToken_MarksVerifiedAndConsumesToken(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("verify-%d", time.Now().UnixNano()))

	tok, err := d.UserSvc.GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if err := d.UserSvc.StoreVerificationToken(context.Background(), u.ID, tok); err != nil {
		t.Fatalf("StoreVerificationToken: %v", err)
	}

	rec := doVerifyEmailRequest(t, d, tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var verified bool
	err = pool.QueryRow(context.Background(), `SELECT email_verified FROM users WHERE id=$1`, u.ID).Scan(&verified)
	if err != nil {
		t.Fatalf("query user: %v", err)
	}
	if !verified {
		t.Error("email_verified was not set to true")
	}

	// Replaying the same token must now fail — it was consumed.
	replay := doVerifyEmailRequest(t, d, tok)
	if replay.Code != http.StatusBadRequest {
		t.Errorf("replayed token status = %d, want %d (token must be single-use)", replay.Code, http.StatusBadRequest)
	}
}

func doResendVerificationRequest(t *testing.T, d Deps, claims *token.AccessTokenClaims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/resend-verification", nil)
	if claims != nil {
		req = withClaims(req, claims)
	}
	rec := httptest.NewRecorder()
	ResendVerification(d)(rec, req)
	return rec
}

// TestResendVerification_NoClaims_Unauthorized proves the endpoint requires
// BearerAuth to have run (claims present in context).
func TestResendVerification_NoClaims_Unauthorized(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})

	rec := doResendVerificationRequest(t, d, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestResendVerification_EmptySub_Unauthorized proves claims with an empty
// Sub (should never happen post-BearerAuth, but defensively checked) are
// also rejected rather than looked up as an empty-string username.
func TestResendVerification_EmptySub_Unauthorized(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})

	rec := doResendVerificationRequest(t, d, &token.AccessTokenClaims{Sub: ""})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestResendVerification_UnknownUser_NotFound proves a token for a deleted
// user is rejected with 404.
func TestResendVerification_UnknownUser_NotFound(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})

	rec := doResendVerificationRequest(t, d, &token.AccessTokenClaims{Sub: fmt.Sprintf("ghost-%d", time.Now().UnixNano())})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestResendVerification_AlreadyVerified_BadRequest proves resending is
// refused once the address is already verified, avoiding pointless email
// spam and confirming the handler actually checks EmailVerified.
func TestResendVerification_AlreadyVerified_BadRequest(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("already-verified-%d", time.Now().UnixNano()))
	if err := d.UserSvc.MarkEmailVerified(context.Background(), u.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}

	rec := doResendVerificationRequest(t, d, &token.AccessTokenClaims{Sub: u.Username})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestResendVerification_UnverifiedUser_StoresNewToken proves the success
// path issues and persists a fresh verification token the user could
// subsequently redeem via VerifyEmail.
func TestResendVerification_UnverifiedUser_StoresNewToken(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	d.Mailer = email.New(email.Config{})
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("resend-%d", time.Now().UnixNano()))

	rec := doResendVerificationRequest(t, d, &token.AccessTokenClaims{Sub: u.Username})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	var count int
	err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM email_verification_tokens WHERE user_id=$1 AND used=false`, u.ID,
	).Scan(&count)
	if err != nil {
		t.Fatalf("query tokens: %v", err)
	}
	if count == 0 {
		t.Error("expected a new unused verification token to be stored")
	}
}
