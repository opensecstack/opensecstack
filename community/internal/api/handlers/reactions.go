package handlers

import (
	"context"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/email"
	"github.com/opensecstack/community/internal/notifications"
)

// GetPostReactions returns per-kind reaction counts and the authenticated
// user's own reactions for a given post.
//
// Response shape:
//
//	{
//	  "reactions":      { "like": 5, "fire": 2 },
//	  "user_reactions": ["like"]
//	}
func GetPostReactions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postID := r.PathValue("id")

		// Per-kind counts — always public.
		rows, err := d.Pool.Query(r.Context(),
			`SELECT kind, COUNT(*) FROM reactions WHERE post_id=$1 GROUP BY kind`,
			postID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		counts := map[string]int{}
		for rows.Next() {
			var kind string
			var cnt int
			if err := rows.Scan(&kind, &cnt); err != nil {
				continue
			}
			counts[kind] = cnt
		}

		// User's own reactions — only if authenticated.
		userReactions := []string{}
		claims := middleware.ClaimsFrom(r.Context())
		if claims != nil {
			var userID string
			if err := d.Pool.QueryRow(r.Context(),
				`SELECT id FROM users WHERE username=$1`, claims.Sub,
			).Scan(&userID); err == nil {
				kindRows, err := d.Pool.Query(r.Context(),
					`SELECT kind FROM reactions WHERE post_id=$1 AND user_id=$2`,
					postID, userID,
				)
				if err == nil {
					defer kindRows.Close()
					for kindRows.Next() {
						var k string
						if err := kindRows.Scan(&k); err == nil {
							userReactions = append(userReactions, k)
						}
					}
				}
			}
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"reactions":      counts,
			"user_reactions": userReactions,
		})
	}
}

func AddReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")

		var req struct {
			Kind string `json:"kind"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var userID string
		err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`INSERT INTO reactions (post_id, user_id, kind) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
			postID, userID, req.Kind,
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		var postAuthorID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT author_id FROM posts WHERE id=$1`, postID).Scan(&postAuthorID); err == nil {
			createNotification(r.Context(), d.Pool, d.Cfg, postAuthorID, userID, "reaction_on_post", &postID, nil)
			if postAuthorID != userID {
				go func(recipientID, pid, kind string) {
					if d.Mailer != nil {
						sendReactionEmail(d.Pool, d.Mailer, recipientID, claims.Sub, kind, pid)
						var slug, title string
						if err := d.Pool.QueryRow(context.Background(), `SELECT slug, title FROM posts WHERE id=$1`, pid).Scan(&slug, &title); err == nil {
							notifications.SendReactionEmail(context.Background(), d.Pool, d.Mailer, d.Cfg, claims.Sub, recipientID, slug, title, kind)
						}
					}
				}(postAuthorID, postID, req.Kind)
			}
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// sendReactionEmail fetches recipient and post details then sends a new-reaction email.
func sendReactionEmail(pool *pgxpool.Pool, mailer *email.Mailer, recipientID, actorUsername, kind, postID string) {
	ctx := context.Background()
	var toAddr, toUsername, postTitle, postSlug string
	if err := pool.QueryRow(ctx, `SELECT email, username FROM users WHERE id=$1`, recipientID).Scan(&toAddr, &toUsername); err != nil || toAddr == "" {
		return
	}
	if err := pool.QueryRow(ctx, `SELECT title, slug FROM posts WHERE id=$1`, postID).Scan(&postTitle, &postSlug); err != nil {
		return
	}
	_ = mailer.SendNewReaction(toAddr, toUsername, actorUsername, kind, postTitle, postSlug)
}

func RemoveReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")
		kind := r.PathValue("kind")

		var userID string
		err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID)
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM reactions WHERE post_id=$1 AND user_id=$2 AND kind=$3`,
			postID, userID, kind,
		)
		w.WriteHeader(http.StatusNoContent)
	}
}
