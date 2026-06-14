package handlers

import (
	"net/http"

	"github.com/jackc/pgx/v5"
)

type userStats struct {
	PostCount     int64 `json:"post_count"`
	ReactionCount int64 `json:"reaction_count"`
	ViewCount     int64 `json:"view_count"`
}

func GetUserStats(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := r.PathValue("username")

		// Resolve user ID from username.
		var authorID string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username = $1`, username,
		).Scan(&authorID)
		if err != nil {
			if err == pgx.ErrNoRows {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		var stats userStats

		// Single round-trip using CTEs.
		err = d.Pool.QueryRow(r.Context(), `
			WITH
			published AS (
				SELECT id FROM posts WHERE author_id = $1 AND state = 'published'
			),
			post_count AS (
				SELECT COUNT(*) AS n FROM published
			),
			reaction_count AS (
				SELECT COUNT(*) AS n
				FROM reactions r
				WHERE r.post_id IN (SELECT id FROM published)
			),
			view_count AS (
				SELECT COALESCE(SUM(pvd.count), 0) AS n
				FROM post_views_daily pvd
				WHERE pvd.post_id IN (SELECT id FROM published)
			)
			SELECT
				(SELECT n FROM post_count),
				(SELECT n FROM reaction_count),
				(SELECT n FROM view_count)
		`, authorID).Scan(&stats.PostCount, &stats.ReactionCount, &stats.ViewCount)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		writeJSON(w, http.StatusOK, stats)
	}
}
