package handlers

import (
	"errors"
	"net/http"
	"time"

	"github.com/opensecstack/opencsirt/internal/auth"
)

type Auth struct {
	Authenticator *auth.Authenticator
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req, 4*1024); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	tok, claims, err := h.Authenticator.Login(req.Username, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrIssuerDisabled):
			writeError(w, http.StatusServiceUnavailable, "issuer_disabled")
			return
		case errors.Is(err, auth.ErrInvalidCreds):
			writeError(w, http.StatusUnauthorized, "invalid_credentials")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"role":       claims.Role,
		"sub":        claims.Sub,
		"expires_at": claims.ExpiresAt.Time.Format(time.RFC3339),
	})
}
