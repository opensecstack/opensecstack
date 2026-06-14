package handlers

import (
	"net/http"

	"github.com/opensecstack/sinauth/internal/api/middleware"
)

// UserInfo handles GET+POST /oauth/userinfo
func UserInfo(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		u, err := d.UserSvc.GetByUsername(r.Context(), claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		uc := &oidcUserClaims{
			Sub:           u.Username,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,
			Name:          u.DisplayName,
			Picture:       u.AvatarURL,
		}
		writeJSON(w, http.StatusOK, uc)
	}
}

type oidcUserClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}
