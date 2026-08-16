package handlers

import (
	"net/http"
)

func GetAdminStats(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(d, r, w, "moderator") {
			return
		}
		ctx := r.Context()

		type tagStat struct {
			Name  string `json:"name"`
			Slug  string `json:"slug"`
			Count int    `json:"count"`
		}
		type userStat struct {
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			PostCount   int    `json:"post_count"`
		}
		type stats struct {
			TotalUsers       int        `json:"total_users"`
			TotalPosts       int        `json:"total_posts"`
			TotalComments    int        `json:"total_comments"`
			TotalReactions   int        `json:"total_reactions"`
			NewUsersThisWeek int        `json:"new_users_this_week"`
			NewPostsThisWeek int        `json:"new_posts_this_week"`
			TopTags          []tagStat  `json:"top_tags"`
			TopAuthors       []userStat `json:"top_authors"`
		}

		var s stats

		// Totals
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE deactivated_at IS NULL`).Scan(&s.TotalUsers)
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM posts WHERE state = 'published'`).Scan(&s.TotalPosts)
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM comments`).Scan(&s.TotalComments)
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM reactions`).Scan(&s.TotalReactions)

		// Weekly
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE created_at > now() - INTERVAL '7 days'`).Scan(&s.NewUsersThisWeek)
		_ = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM posts WHERE state = 'published' AND published_at > now() - INTERVAL '7 days'`).Scan(&s.NewPostsThisWeek)

		// Top tags by post count
		rows, err := d.Pool.Query(ctx, `
			SELECT t.name, t.slug, COUNT(pt.post_id) AS cnt
			FROM tags t
			LEFT JOIN post_tags pt ON pt.tag_id = t.id
			GROUP BY t.id ORDER BY cnt DESC LIMIT 10`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var ts tagStat
				if err := rows.Scan(&ts.Name, &ts.Slug, &ts.Count); err != nil {
					continue
				}
				s.TopTags = append(s.TopTags, ts)
			}
		}

		// Top authors by published post count
		rows2, err := d.Pool.Query(ctx, `
			SELECT u.username, u.display_name, COUNT(p.id) AS cnt
			FROM users u
			LEFT JOIN posts p ON p.author_id = u.id AND p.state = 'published'
			GROUP BY u.id ORDER BY cnt DESC LIMIT 10`)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var us userStat
				if err := rows2.Scan(&us.Username, &us.DisplayName, &us.PostCount); err != nil {
					continue
				}
				s.TopAuthors = append(s.TopAuthors, us)
			}
		}

		if s.TopTags == nil {
			s.TopTags = []tagStat{}
		}
		if s.TopAuthors == nil {
			s.TopAuthors = []userStat{}
		}

		writeJSON(w, http.StatusOK, s)
	}
}
