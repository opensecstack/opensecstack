package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func DeactivateUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil || claims.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		username := r.PathValue("username")
		// Prevent admin from deactivating themselves
		if username == claims.Sub {
			http.Error(w, "cannot deactivate yourself", http.StatusBadRequest)
			return
		}
		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET deactivated_at = now() WHERE username = $1 AND deactivated_at IS NULL`,
			username)
		if err != nil || tag.RowsAffected() == 0 {
			http.Error(w, "not found or already deactivated", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func ReactivateUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil || claims.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		username := r.PathValue("username")
		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE users SET deactivated_at = NULL WHERE username = $1 AND deactivated_at IS NOT NULL`,
			username)
		if err != nil || tag.RowsAffected() == 0 {
			http.Error(w, "not found or not deactivated", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
