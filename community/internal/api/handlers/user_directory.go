package handlers

import (
	"net/http"
)

type directoryUser struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
	Bio         string  `json:"bio"`
	PostCount   int     `json:"post_count"`
}

func ListUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		page := queryInt(r, "page", 1)
		limit := queryInt(r, "limit", 20)
		if limit > 50 {
			limit = 50
		}
		if page < 1 {
			page = 1
		}
		offset := (page - 1) * limit

		const baseWhere = `
			FROM users u
			JOIN posts p ON p.author_id = u.id AND p.state = 'published'
			WHERE ($1 = '' OR u.username ILIKE '%' || $1 || '%' OR u.display_name ILIKE '%' || $1 || '%')
		`

		// Total count query
		var total int
		err := d.Pool.QueryRow(r.Context(),
			`SELECT COUNT(DISTINCT u.id) `+baseWhere, q,
		).Scan(&total)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		// Main query
		rows, err := d.Pool.Query(r.Context(), `
			SELECT u.id, u.username, u.display_name, u.avatar_url, u.bio,
			       COUNT(p.id) AS post_count
			`+baseWhere+`
			GROUP BY u.id, u.username, u.display_name, u.avatar_url, u.bio
			ORDER BY post_count DESC
			LIMIT $2 OFFSET $3`,
			q, limit, offset,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		users := []directoryUser{}
		for rows.Next() {
			var u directoryUser
			if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName, &u.AvatarURL, &u.Bio, &u.PostCount); err != nil {
				continue
			}
			users = append(users, u)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"users": users,
			"total": total,
		})
	}
}
