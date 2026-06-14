package handlers

import (
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/mfa"
)

// claimsUserID resolves the authenticated user's UUID from the token subject (username).
// Returns "" and writes 401 if unauthenticated, or 500 if the user cannot be found.
func claimsUserID(w http.ResponseWriter, r *http.Request, d Deps) (userID string, ok bool) {
	claims := middleware.ClaimsFrom(r.Context())
	if claims == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return "", false
	}
	if err := d.Pool.QueryRow(r.Context(),
		`SELECT id FROM users WHERE username=$1 AND deactivated_at IS NULL`, claims.Sub,
	).Scan(&userID); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
		return "", false
	}
	return userID, true
}

// BeginWebAuthnRegister starts a new passkey/FIDO2 registration ceremony.
// POST /api/v1/mfa/webauthn/register/begin
func BeginWebAuthnRegister(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		waUser, err := mfa.LoadWAUser(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
			return
		}

		options, sessionData, err := d.WebAuthn.BeginRegistration(waUser)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin registration"})
			return
		}

		if err := mfa.StoreWASession(r.Context(), d.Pool, userID, sessionData); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		writeJSON(w, http.StatusOK, options)
	}
}

// FinishWebAuthnRegister completes the registration and saves the credential.
// POST /api/v1/mfa/webauthn/register/finish
func FinishWebAuthnRegister(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		name := r.URL.Query().Get("name")
		if name == "" {
			name = "My Key"
		}

		waUser, err := mfa.LoadWAUser(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user not found"})
			return
		}

		sessionData, err := mfa.LoadAndDeleteWASession(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no active registration session"})
			return
		}

		credential, err := d.WebAuthn.FinishRegistration(waUser, *sessionData, r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "registration failed: " + err.Error()})
			return
		}

		if err := mfa.SaveCredential(r.Context(), d.Pool, userID, name, credential); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to save credential"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
	}
}

// BeginWebAuthnLogin starts a WebAuthn authentication assertion.
// POST /api/v1/mfa/webauthn/login/begin
func BeginWebAuthnLogin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1 AND deactivated_at IS NULL`, req.Username,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		waUser, err := mfa.LoadWAUser(r.Context(), d.Pool, userID)
		if err != nil || len(waUser.Credentials) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no passkeys registered"})
			return
		}

		options, sessionData, err := d.WebAuthn.BeginLogin(waUser)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin login"})
			return
		}

		if err := mfa.StoreWASession(r.Context(), d.Pool, userID, sessionData); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session error"})
			return
		}

		writeJSON(w, http.StatusOK, options)
	}
}

// FinishWebAuthnLogin validates the assertion and issues a sinauth token.
// POST /api/v1/mfa/webauthn/login/finish
func FinishWebAuthnLogin(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		if username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username required"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1 AND deactivated_at IS NULL`, username,
		).Scan(&userID); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}

		waUser, err := mfa.LoadWAUser(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user error"})
			return
		}

		sessionData, err := mfa.LoadAndDeleteWASession(r.Context(), d.Pool, userID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no active login session"})
			return
		}

		credential, err := d.WebAuthn.FinishLogin(waUser, *sessionData, r)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
			return
		}

		mfa.UpdateCredential(r.Context(), d.Pool, credential)

		tok, err := d.Issuer.IssueAccessToken(username, "sinauth-dashboard", []string{"openid", "profile"}, d.Cfg.AccessTokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"access_token": tok, "token_type": "Bearer"})
	}
}

// ListWebAuthnCredentials returns all registered passkeys for the current user.
// GET /api/v1/mfa/webauthn/credentials
func ListWebAuthnCredentials(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		type credInfo struct {
			ID        string  `json:"id"`
			Name      string  `json:"name"`
			CreatedAt string  `json:"created_at"`
			LastUsed  *string `json:"last_used_at,omitempty"`
		}

		rows, err := d.Pool.Query(r.Context(),
			`SELECT encode(credential_id,'base64'), name,
			        to_char(created_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			        to_char(last_used_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
			 FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at`,
			userID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		defer rows.Close()

		var creds []credInfo
		for rows.Next() {
			var c credInfo
			if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.LastUsed); err != nil {
				continue
			}
			creds = append(creds, c)
		}
		if creds == nil {
			creds = []credInfo{}
		}
		writeJSON(w, http.StatusOK, creds)
	}
}

// DeleteWebAuthnCredential removes a passkey by credential ID (base64-encoded).
// DELETE /api/v1/mfa/webauthn/credentials/{id}
func DeleteWebAuthnCredential(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		credID := r.PathValue("id")
		if credID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential id required"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`DELETE FROM webauthn_credentials
			 WHERE user_id=$1 AND encode(credential_id,'base64')=$2`,
			userID, credID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// SendSMSOTP sends a one-time code to the user's registered phone.
// POST /api/v1/mfa/sms/send
func SendSMSOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		var phone string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT COALESCE(phone,'') FROM users WHERE id=$1`, userID,
		).Scan(&phone); err != nil || phone == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no phone number on file"})
			return
		}

		code, err := mfa.GenerateOTP()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "otp generation failed"})
			return
		}

		if err := mfa.StoreSMSOTP(r.Context(), d.Pool, userID, phone, code); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store otp"})
			return
		}

		if err := d.SMS.Send(r.Context(), phone, "SIN verification code: "+code); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to send SMS"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
	}
}

// VerifySMSOTP validates the SMS code.
// POST /api/v1/mfa/sms/verify
func VerifySMSOTP(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := claimsUserID(w, r, d)
		if !ok {
			return
		}

		var req struct {
			Code string `json:"code"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Code == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code required"})
			return
		}

		if !mfa.VerifySMSOTP(r.Context(), d.Pool, userID, req.Code) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired code"})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
	}
}
