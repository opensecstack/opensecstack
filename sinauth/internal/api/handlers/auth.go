package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/sinauth/internal/user"
)

func Login(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		ip := r.RemoteAddr
		ua := r.UserAgent()
		u, err := d.UserSvc.Authenticate(r.Context(), req.Username, req.Password)
		if err != nil {
			if d.Audit != nil {
				d.Audit.Log("login.failure", req.Username, "", ip, ua, nil)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		accessToken, err := d.Issuer.IssueAccessToken(u.Username, "sinauth-dashboard", []string{"openid", "profile", "email"}, d.Cfg.AccessTokenTTL)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token error"})
			return
		}
		if d.Audit != nil {
			d.Audit.Log("login.success", u.Username, "sinauth-dashboard", ip, ua, nil)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   int(d.Cfg.AccessTokenTTL.Seconds()),
			"sub":          u.Username,
			"expires_at":   time.Now().Add(d.Cfg.AccessTokenTTL).Format(time.RFC3339),
		})
	}
}

func Register(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username    string `json:"username"`
			Email       string `json:"email"`
			Password    string `json:"password"`
			DisplayName string `json:"display_name"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.Username == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username is required"})
			return
		}
		if !strings.Contains(req.Email, "@") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email address"})
			return
		}
		if len(req.Password) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}

		ctx := r.Context()
		u, err := d.UserSvc.Create(ctx, req.Username, req.Email, req.Password, req.DisplayName)
		if err != nil {
			if errors.Is(err, user.ErrDuplicate) {
				writeJSON(w, http.StatusConflict, map[string]string{"error": "username or email already taken"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
			return
		}

		token, _ := d.UserSvc.GenerateToken()
		d.UserSvc.StoreVerificationToken(ctx, u.ID, token)
		d.Mailer.SendVerification(u.Email, u.Username, token) //nolint:errcheck

		if d.Audit != nil {
			d.Audit.Log("user.registered", req.Username, "", r.RemoteAddr, r.UserAgent(), nil)
		}

		writeJSON(w, http.StatusCreated, map[string]string{"message": "registered, check email to verify your account"})
	}
}

func ForgotPassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		ctx := r.Context()
		u, err := d.UserSvc.GetByEmail(ctx, req.Email)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]string{"message": "if that email exists, a reset link was sent"})
			return
		}

		token, _ := d.UserSvc.GenerateToken()
		d.UserSvc.StorePasswordResetToken(ctx, u.ID, token)
		d.Mailer.SendPasswordReset(u.Email, token) //nolint:errcheck

		writeJSON(w, http.StatusOK, map[string]string{"message": "if that email exists, a reset link was sent"})
	}
}

func ResetPassword(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token       string `json:"token"`
			NewPassword string `json:"new_password"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if len(req.NewPassword) < 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
			return
		}

		ctx := r.Context()
		userID, err := d.UserSvc.ConsumePasswordResetToken(ctx, req.Token)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired token"})
			return
		}

		hash, _ := d.UserSvc.HashPassword(req.NewPassword)
		d.UserSvc.UpdatePassword(ctx, userID, hash)

		if d.Audit != nil {
			d.Audit.Log("user.password_reset", userID, "", r.RemoteAddr, r.UserAgent(), nil)
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}
