package handlers

import (
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
)

// VerifyEmail handles GET /api/v1/auth/verify-email?token=...
// No authentication required — the token is the credential.
func VerifyEmail(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing token"})
			return
		}

		userID, err := d.UserSvc.ConsumeVerificationToken(r.Context(), token)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired token"})
			return
		}

		if err := d.UserSvc.MarkEmailVerified(r.Context(), userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify email"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "email verified successfully"})
	}
}

// ResendVerification handles POST /api/v1/auth/resend-verification (bearer auth required).
// Reads the user ID from the Bearer token claims set by BearerAuth middleware, then
// generates a new verification token and sends it to the user's registered email.
func ResendVerification(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil || claims.Sub == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		// claims.Sub is the username, not the user ID — every token-issuing
		// handler in this codebase (auth.go, federation.go, social.go,
		// webauthn.go, token.go) sets the JWT "sub" claim to the username, and
		// UserInfo (userinfo.go) reads it back the same way. This previously
		// called GetByID(claims.Sub), which meant this endpoint 404'd for
		// every real user (a username is never a valid user-id UUID) — found
		// by TestResendVerification_UnverifiedUser_StoresNewToken.
		u, err := d.UserSvc.GetByUsername(r.Context(), claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		if u.EmailVerified {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email already verified"})
			return
		}

		token, err := d.UserSvc.GenerateToken()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
			return
		}
		if err := d.UserSvc.StoreVerificationToken(r.Context(), u.ID, token); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not store token"})
			return
		}
		_ = d.Mailer.SendVerification(u.Email, u.Username, token) // ignore error — dev mode skips sending

		writeJSON(w, http.StatusOK, map[string]string{"message": "verification email sent"})
	}
}
