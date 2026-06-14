package handlers

// Wire in server.go:
//   mux.Handle("GET /api/v1/posts/{id}/analytics", auth(http.HandlerFunc(handlers.GetPostAnalytics(d))))

import (
	"net/http"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

type dayCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

type postAnalyticsResponse struct {
	TotalViews int64      `json:"total_views"`
	Days       []dayCount `json:"days"`
}

func GetPostAnalytics(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		postID := r.PathValue("id")

		// Verify the requesting user owns this post (admins can bypass).
		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT author_id FROM posts WHERE id = $1`, postID,
		).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found"})
			return
		}

		if !auth.HasRole(claims.Role, "admin") {
			// Non-admins must be the author — look up the requesting user's ID.
			var requesterID string
			if err := d.Pool.QueryRow(r.Context(),
				`SELECT id FROM users WHERE username = $1`, claims.Sub,
			).Scan(&requesterID); err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
				return
			}
			if requesterID != authorID {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
		}

		// Fetch total views.
		var totalViews int64
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT views FROM posts WHERE id = $1`, postID,
		).Scan(&totalViews); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Fetch last 30 days of daily view data.
		rows, err := d.Pool.Query(r.Context(),
			`SELECT day::text, count
			 FROM post_views_daily
			 WHERE post_id = $1 AND day >= CURRENT_DATE - INTERVAL '29 days'
			 ORDER BY day ASC`,
			postID,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		// Build a map from the query results.
		dbCounts := make(map[string]int64)
		for rows.Next() {
			var day string
			var count int64
			if err := rows.Scan(&day, &count); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			dbCounts[day] = count
		}
		if err := rows.Err(); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Generate a full 30-day series, filling missing days with 0.
		today := time.Now().UTC().Truncate(24 * time.Hour)
		days := make([]dayCount, 30)
		for i := 0; i < 30; i++ {
			d := today.AddDate(0, 0, i-29)
			key := d.Format("2006-01-02")
			days[i] = dayCount{
				Date:  key,
				Count: dbCounts[key],
			}
		}

		writeJSON(w, http.StatusOK, postAnalyticsResponse{
			TotalViews: totalViews,
			Days:       days,
		})
	}
}
