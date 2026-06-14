package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

func AddCommentReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		commentID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, err := d.Pool.Exec(r.Context(),
			`INSERT INTO comment_reactions (comment_id, user_id, kind) VALUES ($1,$2,'heart') ON CONFLICT DO NOTHING`,
			commentID, userID,
		)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func RemoveCommentReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		commentID := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`DELETE FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND kind='heart'`,
			commentID, userID,
		)

		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func ToggleCommentReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		commentID := r.PathValue("id")
		var req struct {
			Kind string `json:"kind"`
		}
		if err := decodeJSON(r, &req); err != nil || req.Kind == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var userID string
		err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username = $1`, claims.Sub).Scan(&userID)
		if err != nil {
			http.Error(w, "user not found", http.StatusUnauthorized)
			return
		}

		var exists bool
		d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND kind=$3)`,
			commentID, userID, req.Kind).Scan(&exists)

		if exists {
			d.Pool.Exec(r.Context(),
				`DELETE FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND kind=$3`,
				commentID, userID, req.Kind)
		} else {
			d.Pool.Exec(r.Context(),
				`INSERT INTO comment_reactions (comment_id, user_id, kind) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
				commentID, userID, req.Kind)
		}

		// Return updated counts
		rows, err := d.Pool.Query(r.Context(),
			`SELECT kind, COUNT(*) FROM comment_reactions WHERE comment_id=$1 GROUP BY kind`, commentID)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"counts": map[string]int{}})
			return
		}
		defer rows.Close()
		counts := map[string]int{}
		for rows.Next() {
			var kind string
			var cnt int
			rows.Scan(&kind, &cnt)
			counts[kind] = cnt
		}
		// Include whether current user has each reaction
		userReactions := map[string]bool{}
		for _, k := range []string{"heart", "unicorn", "fire"} {
			var has bool
			d.Pool.QueryRow(r.Context(),
				`SELECT EXISTS(SELECT 1 FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND kind=$3)`,
				commentID, userID, k).Scan(&has)
			userReactions[k] = has
		}
		writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "user_reactions": userReactions})
	}
}

func GetCommentReactions(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		commentID := r.PathValue("id")
		rows, err := d.Pool.Query(r.Context(),
			`SELECT kind, COUNT(*) FROM comment_reactions WHERE comment_id=$1 GROUP BY kind`, commentID)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"counts": map[string]int{}})
			return
		}
		defer rows.Close()
		counts := map[string]int{}
		for rows.Next() {
			var kind string
			var cnt int
			rows.Scan(&kind, &cnt)
			counts[kind] = cnt
		}

		userReactions := map[string]bool{}
		claims := middleware.ClaimsFrom(r.Context())
		if claims != nil {
			var userID string
			if err2 := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err2 == nil {
				for _, k := range []string{"heart", "unicorn", "fire"} {
					var has bool
					d.Pool.QueryRow(r.Context(),
						`SELECT EXISTS(SELECT 1 FROM comment_reactions WHERE comment_id=$1 AND user_id=$2 AND kind=$3)`,
						commentID, userID, k).Scan(&has)
					userReactions[k] = has
				}
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"counts": counts, "user_reactions": userReactions})
	}
}
