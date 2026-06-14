package handlers

import (
	"net/http"
	"strings"
)

type autocompletePost struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
	Slug  string `json:"slug"`
}

type autocompleteTag struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type autocompleteUser struct {
	Username    string  `json:"username"`
	DisplayName *string `json:"display_name"`
	AvatarURL   *string `json:"avatar_url"`
}

type autocompleteResponse struct {
	Posts []autocompletePost `json:"posts"`
	Tags  []autocompleteTag  `json:"tags"`
	Users []autocompleteUser `json:"users"`
}

func Autocomplete(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := strings.TrimSpace(r.URL.Query().Get("q"))
		if len(q) < 2 {
			writeJSON(w, http.StatusOK, autocompleteResponse{
				Posts: []autocompletePost{},
				Tags:  []autocompleteTag{},
				Users: []autocompleteUser{},
			})
			return
		}
		pattern := "%" + q + "%"

		// Posts (published only)
		postRows, err := d.Pool.Query(r.Context(),
			`SELECT id, title, slug FROM posts
			 WHERE state = 'published' AND title ILIKE $1
			 ORDER BY published_at DESC LIMIT 3`,
			pattern,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer postRows.Close()

		posts := []autocompletePost{}
		for postRows.Next() {
			var p autocompletePost
			if err := postRows.Scan(&p.ID, &p.Title, &p.Slug); err != nil {
				continue
			}
			posts = append(posts, p)
		}
		postRows.Close()

		// Tags
		tagRows, err := d.Pool.Query(r.Context(),
			`SELECT slug, name FROM tags
			 WHERE name ILIKE $1 OR slug ILIKE $1
			 ORDER BY name LIMIT 3`,
			pattern,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer tagRows.Close()

		tags := []autocompleteTag{}
		for tagRows.Next() {
			var t autocompleteTag
			if err := tagRows.Scan(&t.Slug, &t.Name); err != nil {
				continue
			}
			tags = append(tags, t)
		}
		tagRows.Close()

		// Users
		userRows, err := d.Pool.Query(r.Context(),
			`SELECT username, display_name, avatar_url FROM users
			 WHERE username ILIKE $1 OR display_name ILIKE $1
			 ORDER BY username LIMIT 3`,
			pattern,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer userRows.Close()

		users := []autocompleteUser{}
		for userRows.Next() {
			var u autocompleteUser
			if err := userRows.Scan(&u.Username, &u.DisplayName, &u.AvatarURL); err != nil {
				continue
			}
			users = append(users, u)
		}
		userRows.Close()

		writeJSON(w, http.StatusOK, autocompleteResponse{
			Posts: posts,
			Tags:  tags,
			Users: users,
		})
	}
}
