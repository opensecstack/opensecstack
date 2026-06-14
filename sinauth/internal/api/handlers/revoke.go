package handlers

import "net/http"

func Revoke(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		raw := r.FormValue("token")
		if raw == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		// Best-effort revocation per RFC 7009 — always return 200
		_ = d.TokenStore.RevokeRefreshToken(r.Context(), raw)
		w.WriteHeader(http.StatusOK)
	}
}
