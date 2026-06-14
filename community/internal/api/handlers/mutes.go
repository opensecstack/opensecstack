package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func MuteUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var muterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&muterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "muter user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var mutedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&mutedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		if muterID == mutedID {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot mute yourself"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO user_mutes(muter_id, muted_id) VALUES($1,$2) ON CONFLICT DO NOTHING`,
			muterID, mutedID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnmuteUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var muterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&muterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "muter user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var mutedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&mutedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM user_mutes WHERE muter_id=$1 AND muted_id=$2`,
			muterID, mutedID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetMuteStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var muterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&muterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "muter user not found"})
			return
		}

		targetUsername := r.PathValue("username")
		var mutedID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&mutedID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM user_mutes WHERE muter_id=$1 AND muted_id=$2)`,
			muterID, mutedID,
		).Scan(&exists)
		writeJSON(w, http.StatusOK, map[string]bool{"muted": exists})
	}
}

type mutedUser struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
}

func ListMutedUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var muterID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&muterID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		rows, err := d.Pool.Query(r.Context(),
			`SELECT u.id, u.username, u.display_name, u.avatar_url
			 FROM user_mutes m
			 JOIN users u ON u.id = m.muted_id
			 WHERE m.muter_id = $1
			 ORDER BY m.created_at DESC`,
			muterID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := make([]mutedUser, 0)
		for rows.Next() {
			var u mutedUser
			if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.AvatarURL); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			users = append(users, u)
		}

		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	}
}
