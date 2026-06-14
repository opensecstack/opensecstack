package handlers

import (
	"net/http"
)

type leaderboardUser struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Bio         string  `json:"bio"`
}

type leaderboardEntry struct {
	Rank           int             `json:"rank"`
	User           leaderboardUser `json:"user"`
	PostCount      int64           `json:"post_count"`
	TotalReactions int64           `json:"total_reactions"`
	TotalViews     int64           `json:"total_views"`
	Score          int64           `json:"score"`
}

func GetLeaderboard(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		period := r.URL.Query().Get("period")
		if period != "month" {
			period = "week"
		}

		interval := "7 days"
		if period == "month" {
			interval = "30 days"
		}

		// $1 is cast to interval so pgx sends it as a plain string.
		rows, err := d.Pool.Query(r.Context(), `
			SELECT
				u.id,
				u.username,
				u.display_name,
				u.avatar_url,
				u.bio,
				COUNT(DISTINCT p.id)                                          AS post_count,
				COALESCE(SUM(
					(SELECT COUNT(*) FROM reactions rx WHERE rx.post_id = p.id)
				), 0)                                                          AS total_reactions,
				COALESCE(SUM(p.views), 0)                                     AS total_views,
				COALESCE(SUM(
					(SELECT COUNT(*) FROM reactions rx WHERE rx.post_id = p.id)
				), 0) * 3 + COALESCE(SUM(p.views), 0)                        AS score
			FROM users u
			JOIN posts p ON p.author_id = u.id
			WHERE p.state = 'published'
			  AND p.published_at >= NOW() - $1::interval
			GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
			ORDER BY score DESC
			LIMIT 20`,
			interval,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		entries := []leaderboardEntry{}
		rank := 1
		for rows.Next() {
			var e leaderboardEntry
			if err := rows.Scan(
				&e.User.ID,
				&e.User.Username,
				&e.User.DisplayName,
				&e.User.AvatarURL,
				&e.User.Bio,
				&e.PostCount,
				&e.TotalReactions,
				&e.TotalViews,
				&e.Score,
			); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			e.Rank = rank
			rank++
			entries = append(entries, e)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"period":  period,
			"entries": entries,
		})
	}
}
