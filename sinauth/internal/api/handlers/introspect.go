package handlers

import (
	"net/http"
	"strings"
)

func Introspect(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		raw := r.FormValue("token")
		claims, err := d.Verifier.Verify(raw)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active":    true,
			"sub":       claims.Sub,
			"client_id": claims.ClientID,
			"scope":     strings.Join(claims.Scopes, " "),
			"exp":       claims.ExpiresAt.Unix(),
			"iat":       claims.IssuedAt.Unix(),
			"iss":       claims.Issuer,
		})
	}
}
