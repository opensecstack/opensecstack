package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/email"
	"github.com/opensecstack/community/internal/notifications"
)

type followUser struct {
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Badge       *string `json:"platform_badge"`
}

type followListResponse struct {
	Users []followUser `json:"users"`
	Count int          `json:"count"`
}

func FollowUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		targetUsername := r.PathValue("username")

		if claims.Sub == targetUsername {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot follow yourself"})
			return
		}

		var followerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&followerID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "follower user not found"})
			return
		}

		var followingID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&followingID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "target user not found"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO follows (follower_id, following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			followerID, followingID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		createNotification(r.Context(), d.Pool, d.Cfg, followingID, followerID, "new_follower", nil, nil)
		go func(recipientID string) {
			if d.Mailer != nil {
				sendFollowerEmail(d.Pool, d.Mailer, recipientID, claims.Sub)
				if err := notifications.SendFollowEmail(context.Background(), d.Pool, d.Mailer, d.Cfg, claims.Sub, recipientID); err != nil {
					slog.Error("Follow: send follow email failed", "recipient_id", recipientID, "err", err)
				}
			}
		}(followingID)

		w.WriteHeader(http.StatusNoContent)
	}
}

// sendFollowerEmail fetches the followed user's email and sends a new-follower notification.
func sendFollowerEmail(pool *pgxpool.Pool, mailer *email.Mailer, recipientID, actorUsername string) {
	ctx := context.Background()
	var toAddr, toUsername string
	if err := pool.QueryRow(ctx, `SELECT email, username FROM users WHERE id=$1`, recipientID).Scan(&toAddr, &toUsername); err != nil || toAddr == "" {
		return
	}
	_ = mailer.SendNewFollower(toAddr, toUsername, actorUsername)
}

func UnfollowUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		targetUsername := r.PathValue("username")

		var followerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&followerID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		var followingID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&followingID); err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM follows WHERE follower_id=$1 AND following_id=$2`,
			followerID, followingID,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}

func ListFollowers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
SELECT u.username, u.display_name, u.avatar_url, u.platform_badge
FROM follows f
JOIN users u ON u.id = f.follower_id
JOIN users target ON target.id = f.following_id AND target.username = $1
ORDER BY f.created_at DESC
LIMIT $2 OFFSET $3`,
			username, limit, offset,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := []followUser{}
		for rows.Next() {
			var u followUser
			if err := rows.Scan(&u.Username, &u.DisplayName, &u.AvatarURL, &u.Badge); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			users = append(users, u)
		}
		writeJSON(w, http.StatusOK, followListResponse{Users: users, Count: len(users)})
	}
}

func ListFollowing(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		rows, err := d.Pool.Query(r.Context(), `
SELECT u.username, u.display_name, u.avatar_url, u.platform_badge
FROM follows f
JOIN users u ON u.id = f.following_id
JOIN users src ON src.id = f.follower_id AND src.username = $1
ORDER BY f.created_at DESC
LIMIT $2 OFFSET $3`,
			username, limit, offset,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := []followUser{}
		for rows.Next() {
			var u followUser
			if err := rows.Scan(&u.Username, &u.DisplayName, &u.AvatarURL, &u.Badge); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			users = append(users, u)
		}
		writeJSON(w, http.StatusOK, followListResponse{Users: users, Count: len(users)})
	}
}

func GetFollowCounts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")
		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, username).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, map[string]int{"followers": 0, "following": 0})
			return
		}
		var followers, following int
		_ = d.Pool.QueryRow(r.Context(), `SELECT count(*) FROM follows WHERE following_id=$1`, userID).Scan(&followers)
		_ = d.Pool.QueryRow(r.Context(), `SELECT count(*) FROM follows WHERE follower_id=$1`, userID).Scan(&following)
		writeJSON(w, http.StatusOK, map[string]int{"followers": followers, "following": following})
	}
}

func GetFollowStatus(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		targetUsername := r.PathValue("username")

		var followerID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&followerID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"following": false})
			return
		}

		var followingID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, targetUsername).Scan(&followingID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"following": false})
			return
		}

		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM follows WHERE follower_id=$1 AND following_id=$2)`,
			followerID, followingID,
		).Scan(&exists)
		writeJSON(w, http.StatusOK, map[string]bool{"following": exists})
	}
}
