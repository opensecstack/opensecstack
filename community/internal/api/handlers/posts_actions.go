package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/mentions"
	"github.com/opensecstack/community/internal/search"
)

func PublishPost(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1 AND p.state='draft'`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "post not found or not in draft"})
			return
		}
		if authorUsername != claims.Sub && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		_, err = d.Pool.Exec(r.Context(),
			`UPDATE posts SET state='published', published_at=now(), updated_at=now() WHERE id=$1`, id,
		)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		_ = d.Citadel.Emit(r.Context(), citadel.Event{
			Kind:      "community.post.published",
			NodeID:    d.Cfg.Node,
			Timestamp: time.Now(),
			Payload:   map[string]any{"post_id": id, "author": claims.Sub},
		})

		if d.Search != nil {
			var title, slug, displayName string
			var body, publishedAt *string
			_ = d.Pool.QueryRow(r.Context(),
				`SELECT p.title, p.slug, p.body, p.published_at::text, u.display_name
				 FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
			).Scan(&title, &slug, &body, &publishedAt, &displayName)
			var tagNames []string
			tagRows, _ := d.Pool.Query(r.Context(),
				`SELECT t.name FROM tags t JOIN post_tags pt ON pt.tag_id = t.id WHERE pt.post_id = $1`, id)
			if tagRows != nil {
				for tagRows.Next() {
					var name string
					if tagRows.Scan(&name) == nil {
						tagNames = append(tagNames, name)
					}
				}
				tagRows.Close()
			}
			bodyStr := ""
			if body != nil {
				bodyStr = *body
			}
			pubAt := ""
			if publishedAt != nil {
				pubAt = *publishedAt
			}
			_ = d.Search.IndexPost(search.PostDocument{
				ID:                id,
				Title:             title,
				Body:              bodyStr,
				AuthorUsername:    claims.Sub,
				AuthorDisplayName: displayName,
				Tags:              tagNames,
				PublishedAt:       pubAt,
				Slug:              slug,
			})
		}

		// Fire mention notifications for any @username found in the post body.
		go func() {
			var postBody, authorID string
			if err := d.Pool.QueryRow(context.Background(),
				`SELECT COALESCE(p.body,''), u.id FROM posts p JOIN users u ON u.id = p.author_id WHERE p.id = $1`, id,
			).Scan(&postBody, &authorID); err != nil {
				return
			}
			usernames := mentions.Extract(postBody)
			if len(usernames) > 0 {
				if err := mentions.NotifyMentions(context.Background(), d.Pool, authorID, usernames, id, ""); err != nil {
					slog.Error("PublishPost: notify mentions failed", "post_id", id, "err", err)
				}
			}
		}()

		writeJSON(w, http.StatusOK, map[string]string{"id": id, "state": "published"})
	}
}

func ListFollowingFeed(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		var userID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusOK, postListResponse{Posts: []postRow{}, Count: 0})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT p.id, p.author_id, u.username, u.display_name, u.avatar_url, u.platform_badge,
			       p.title, p.slug, p.cover_image_url, p.state,
			       p.published_at::text, p.created_at::text, p.updated_at::text, p.scheduled_at::text,
			       p.edited_at::text,
			       COALESCE(array_agg(t.name) FILTER (WHERE t.name IS NOT NULL), '{}') AS tags,
			       (SELECT count(*) FROM reactions r WHERE r.post_id = p.id) AS reaction_count,
			       (SELECT count(*) FROM comments c WHERE c.post_id = p.id) AS comment_count,
			       p.views, p.locked, p.pinned, p.sensitive
			FROM posts p
			JOIN users u ON u.id = p.author_id
			JOIN follows f ON f.following_id = p.author_id AND f.follower_id = $1
			LEFT JOIN post_tags pt ON pt.post_id = p.id
			LEFT JOIN tags t ON t.id = pt.tag_id
			LEFT JOIN blocks bl ON bl.blocker_id = $1 AND bl.blocked_id = p.author_id
			WHERE p.state = 'published' AND bl.blocked_id IS NULL
			GROUP BY p.id, u.id
			ORDER BY p.pinned DESC, p.published_at DESC
			LIMIT $2 OFFSET $3`, userID, limit, offset)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var posts []postRow
		for rows.Next() {
			var p postRow
			var tags []string
			if err := rows.Scan(scanPost(&p, &tags)...); err != nil {
				continue
			}
			p.Tags = tags
			posts = append(posts, p)
		}
		if posts == nil {
			posts = []postRow{}
		}
		writeJSON(w, http.StatusOK, postListResponse{Posts: posts, Count: len(posts)})
	}
}

func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
		} else if c == ' ' || c == '-' {
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
