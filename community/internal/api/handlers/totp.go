package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/opensecstack/community/internal/api/middleware"
)

// totpStepPeriod matches pquerna/otp's default Period (30s, RFC 6238).
const totpStepPeriod = 30 * time.Second

// ConsumeTOTPCode validates code against secret and, only on success,
// atomically claims the current time-step for username so the same code
// can never be accepted twice. totp.Validate alone has no anti-replay —
// with the library's default Skew:1 a valid code is accepted across a
// ~90-second sliding window with nothing to stop it being submitted
// repeatedly within that window (e.g. to disable 2FA twice, or log in
// twice, with a single captured code). The claim is a single
// UPDATE ... WHERE totp_last_step IS NULL OR totp_last_step < $step
// RETURNING id, so two concurrent requests racing the same code can only
// ever have one of them succeed — mirroring the single-use pattern this
// codebase already uses for password-reset tokens.
//
// Used by ConfirmTOTP, DisableTOTP (this file), and Login (auth.go) — the
// three places that ever check a live TOTP code.
func ConsumeTOTPCode(ctx context.Context, pool *pgxpool.Pool, username, code, secret string) bool {
	if !totp.Validate(code, secret) {
		return false
	}
	step := time.Now().Unix() / int64(totpStepPeriod/time.Second)
	var id string
	err := pool.QueryRow(ctx, `
		UPDATE users SET totp_last_step = $2
		WHERE username = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)
		RETURNING id`,
		username, step,
	).Scan(&id)
	// Any error — including pgx.ErrNoRows, meaning this step was already
	// claimed by an earlier use of the same code — fails closed. An
	// unexpected DB error must not silently disable replay protection.
	return err == nil
}

// SetupTOTP generates a new TOTP secret, stores it server-side in totp_setup_sessions,
// and returns only a setup_id and a base64-encoded QR image. The secret never leaves
// the server, preventing it from being captured in access logs or proxy logs (H5 fix).
// POST /api/v1/me/totp/setup
func SetupTOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "SIN",
			AccountName: claims.Sub,
		})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate TOTP secret"})
			return
		}

		// Store secret in DB; return only setup_id to client (secret never leaves server)
		var setupID string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO totp_setup_sessions (username, secret)
             VALUES ($1, $2) RETURNING setup_id`,
			claims.Sub, key.Secret(),
		).Scan(&setupID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store TOTP session"})
			return
		}

		// Generate QR code as base64 PNG so the raw secret URL doesn't appear in JSON
		img, err := key.Image(200, 200)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate QR code"})
			return
		}
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode QR code"})
			return
		}
		qrDataURL := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

		writeJSON(w, http.StatusOK, map[string]string{
			"setup_id": setupID,
			"qr_code":  qrDataURL,
		})
	}
}

// ConfirmTOTP validates the provided OTP code against the secret stored server-side
// for the given setup_id, then persists the secret and marks TOTP as enabled.
// The setup session is deleted atomically on use to prevent replay.
// POST /api/v1/me/totp/confirm
func ConfirmTOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			SetupID string `json:"setup_id"`
			Code    string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if req.SetupID == "" || req.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "setup_id and code are required"})
			return
		}

		// Retrieve and atomically delete the session; username check prevents one user
		// from confirming another user's setup session.
		var secret string
		err := d.Pool.QueryRow(r.Context(),
			`DELETE FROM totp_setup_sessions
             WHERE setup_id = $1 AND username = $2 AND expires_at > now()
             RETURNING secret`,
			req.SetupID, claims.Sub,
		).Scan(&secret)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired setup session"})
			return
		}

		if !ConsumeTOTPCode(r.Context(), d.Pool, claims.Sub, req.Code, secret) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE users SET totp_secret=$1, totp_enabled=true WHERE username=$2`,
			secret, claims.Sub,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save TOTP secret"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"enabled": true})
	}
}

// DisableTOTP verifies the current OTP code and then clears TOTP for the user.
// DELETE /api/v1/me/totp
func DisableTOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var req struct {
			Code string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		// Fetch the current secret so we can verify the code before disabling.
		var secret string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT COALESCE(totp_secret,'') FROM users WHERE username=$1`,
			claims.Sub,
		).Scan(&secret)
		if err != nil || secret == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "2FA is not enabled"})
			return
		}

		if !ConsumeTOTPCode(r.Context(), d.Pool, claims.Sub, req.Code, secret) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid 2FA code"})
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE users SET totp_secret=NULL, totp_enabled=false WHERE username=$1`,
			claims.Sub,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to disable 2FA"})
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// GetTOTPStatus returns whether TOTP is currently enabled for the authenticated user.
// GET /api/v1/me/totp
func GetTOTPStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var enabled bool
		err := d.Pool.QueryRow(r.Context(),
			`SELECT COALESCE(totp_enabled, false) FROM users WHERE username=$1`,
			claims.Sub,
		).Scan(&enabled)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"enabled": enabled})
	}
}
