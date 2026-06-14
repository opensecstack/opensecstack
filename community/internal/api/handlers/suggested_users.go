package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

type suggestedUserRow struct {
	Username      string  `json:"username"`
	DisplayName   string  `json:"display_name"`
	AvatarURL     *string `json:"avatar_url"`
	Bio           string  `json:"bio"`
	FollowerCount int64   `json:"follower_count"`
}

func GetSuggestedUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())

		// Use empty string when unauthenticated so the WHERE clause excludes nobody.
		currentUsername := ""
		if claims != nil {
			currentUsername = claims.Sub
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT u.username, u.display_name, u.avatar_url, COALESCE(u.bio, ''),
			       COUNT(f.follower_id) AS follower_count
			FROM users u
			LEFT JOIN follows f ON f.following_id = u.id
			WHERE ($1 = '' OR u.username != $1)
			  AND ($1 = '' OR NOT EXISTS (
			        SELECT 1 FROM follows f2
			        JOIN users me ON me.id = f2.follower_id AND me.username = $1
			        WHERE f2.following_id = u.id
			      ))
			GROUP BY u.id
			ORDER BY follower_count DESC
			LIMIT 5`,
			currentUsername,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := []suggestedUserRow{}
		for rows.Next() {
			var u suggestedUserRow
			if err := rows.Scan(&u.Username, &u.DisplayName, &u.AvatarURL, &u.Bio, &u.FollowerCount); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			users = append(users, u)
		}

		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	}
}
