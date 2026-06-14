package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func SubscribePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		postID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, claims.Sub).Scan(&userID); err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		// Verify post exists
		var exists bool
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM posts WHERE id = $1)`, postID).Scan(&exists); err != nil || !exists {
			http.Error(w, "post not found", http.StatusNotFound)
			return
		}

		if _, err := d.Pool.Exec(r.Context(),
			`INSERT INTO post_subscriptions (user_id, post_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			userID, postID); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func UnsubscribePost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		postID := r.PathValue("id")

		if _, err := d.Pool.Exec(r.Context(),
			`DELETE FROM post_subscriptions ps
             USING users u
             WHERE u.username = $1 AND ps.user_id = u.id AND ps.post_id = $2`,
			claims.Sub, postID); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func GetPostSubscriptionStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		postID := r.PathValue("id")

		var subscribed bool
		if err := d.Pool.QueryRow(r.Context(), `
            SELECT EXISTS (
                SELECT 1 FROM post_subscriptions ps
                JOIN users u ON u.id = ps.user_id
                WHERE u.username = $1 AND ps.post_id = $2
            )`, claims.Sub, postID).Scan(&subscribed); err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"subscribed": subscribed})
	}
}
