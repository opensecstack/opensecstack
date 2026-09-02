package handlers

import (
	"errors"
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/mfa"
)

// BeginTOTPEnroll starts TOTP MFA enrollment: generates a new secret and
// parks it as a pending totp_setup_sessions row (10-minute TTL). The secret
// is only returned here, at generation time — once ConfirmTOTPEnroll
// succeeds, it is never displayed again.
// POST /api/v1/mfa/totp/enroll/begin
func BeginTOTPEnroll(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}
		claims := middleware.ClaimsFrom(r.Context())

		setupID, secret, otpauthURL, err := mfa.BeginTOTPSetup(r.Context(), d.Pool, userID, claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin totp enrollment"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"setup_id":    setupID,
			"secret":      secret,
			"otpauth_url": otpauthURL,
		})
	}
}

// ConfirmTOTPEnroll completes enrollment: the caller proves possession of
// the secret by submitting a valid 6-digit code, which promotes the pending
// setup session into an active totp_credentials row and issues a one-time
// set of backup codes. The backup codes are returned in this response only
// — they are stored as bcrypt hashes and can never be retrieved again.
// POST /api/v1/mfa/totp/enroll/confirm
func ConfirmTOTPEnroll(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		var req struct {
			SetupID string `json:"setup_id"`
			Code    string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil || req.SetupID == "" || req.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "setup_id and code are required"})
			return
		}

		backupCodes, err := mfa.ConfirmTOTPSetup(r.Context(), d.Pool, userID, req.SetupID, req.Code, d.Cfg.BcryptCost)
		if err != nil {
			switch {
			case errors.Is(err, mfa.ErrNoPendingSetup), errors.Is(err, mfa.ErrSetupExpired):
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no active setup session for this user (it may have expired — start enrollment again)"})
			case errors.Is(err, mfa.ErrInvalidCode):
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
			default:
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to confirm totp enrollment"})
			}
			return
		}

		if d.Audit != nil {
			d.Audit.Log("mfa.totp_enabled", userID, "", r.RemoteAddr, r.UserAgent(), nil)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":       "enabled",
			"backup_codes": backupCodes,
		})
	}
}

// TOTPStatus reports whether the current user has TOTP enabled.
// GET /api/v1/mfa/totp/status
func TOTPStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}
		enabled, err := mfa.IsTOTPEnabled(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}

// DisableTOTP turns off TOTP MFA for the current user. This requires
// re-proving current possession of the second factor (a valid TOTP code or
// a backup code) — an authenticated session alone is deliberately NOT
// sufficient, so a hijacked bearer token can't be used to strip MFA off an
// account and downgrade its security.
// POST /api/v1/mfa/totp/disable
func DisableTOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		var req struct {
			Code string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
			return
		}

		enabled, err := mfa.IsTOTPEnabled(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		if !enabled {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "totp is not enabled"})
			return
		}

		verifyErr := mfa.VerifyTOTPCode(r.Context(), d.Pool, userID, req.Code)
		if verifyErr != nil && !mfa.VerifyTOTPBackupCode(r.Context(), d.Pool, userID, req.Code) {
			status := http.StatusUnauthorized
			if errors.Is(verifyErr, mfa.ErrLocked) {
				status = http.StatusTooManyRequests
			}
			writeJSON(w, status, map[string]string{"error": "invalid code"})
			return
		}

		if err := mfa.DisableTOTPCredential(r.Context(), d.Pool, userID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable totp"})
			return
		}

		if d.Audit != nil {
			d.Audit.Log("mfa.totp_disabled", userID, "", r.RemoteAddr, r.UserAgent(), nil)
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
	}
}

// VerifyTOTPLogin completes the two-phase login flow for a user with TOTP
// enabled: Login (auth.go) verifies the password but withholds the token,
// returning a challenge_id instead. This endpoint redeems that challenge
// with a TOTP code (or a backup code, as a fallback) and issues the access
// token that a normal password-only Login would have issued directly.
// POST /api/v1/mfa/totp/login/verify
func VerifyTOTPLogin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ChallengeID string `json:"challenge_id"`
			Code        string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil || req.ChallengeID == "" || req.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_id and code are required"})
			return
		}

		userID, username, err := mfa.ResolveTOTPLoginChallenge(r.Context(), d.Pool, req.ChallengeID)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired challenge"})
			return
		}

		verifyErr := mfa.VerifyTOTPCode(r.Context(), d.Pool, userID, req.Code)
		usedBackup := false
		if verifyErr != nil {
			if !mfa.VerifyTOTPBackupCode(r.Context(), d.Pool, userID, req.Code) {
				if d.Audit != nil {
					d.Audit.Log("login.mfa_failure", username, "", r.RemoteAddr, r.UserAgent(), nil)
				}
				status := http.StatusUnauthorized
				if errors.Is(verifyErr, mfa.ErrLocked) {
					status = http.StatusTooManyRequests
				}
				writeJSON(w, status, map[string]string{"error": "invalid code"})
				return
			}
			usedBackup = true
		}

		// The challenge is single-use — consume it only now, on a proven
		// successful code, so a mistyped first attempt doesn't force the
		// user to restart the entire password login.
		mfa.DeleteTOTPLoginChallenge(r.Context(), d.Pool, req.ChallengeID)

		accessToken, err := d.Issuer.IssueAccessToken(username, "sinauth-dashboard", []string{"openid", "profile", "email"}, d.Cfg.AccessTokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}

		if d.Audit != nil {
			event := "login.success"
			if usedBackup {
				event = "login.success.totp_backup_code"
			}
			d.Audit.Log(event, username, "sinauth-dashboard", r.RemoteAddr, r.UserAgent(), nil)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   int(d.Cfg.AccessTokenTTL.Seconds()),
			"sub":          username,
		})
	}
}
