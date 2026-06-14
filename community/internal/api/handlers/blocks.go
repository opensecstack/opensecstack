package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func BlockUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var blockerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&blockerID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "blocker user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var blockedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&blockedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		if blockerID == blockedID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot block yourself"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			blockerID, blockedID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnblockUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var blockerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&blockerID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "blocker user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var blockedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&blockedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM blocks WHERE blocker_id=$1 AND blocked_id=$2`,
			blockerID, blockedID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetBlockStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var blockerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&blockerID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "blocker user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var blockedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&blockedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM blocks WHERE blocker_id=$1 AND blocked_id=$2)`,
			blockerID, blockedID,
		).Scan(&exists)
		writeJSON(w, http.StatusOK, map[string]bool{"blocking": exists})
	}
}
