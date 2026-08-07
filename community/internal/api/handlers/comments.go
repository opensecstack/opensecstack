package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/email"
	"github.com/opensecstack/community/internal/mentions"
	"github.com/opensecstack/community/internal/notifications"
)

// commentSelectSQL is the common SELECT/FROM/JOIN fragment used when fetching
// comment rows into commentRow. Callers append WHERE, ORDER BY, LIMIT, and
// OFFSET clauses, then scan with the commentRow field order.
const commentSelectSQL = `
	SELECT c.id, c.post_id, c.parent_id, c.author_id,
	       u.username, u.display_name, u.avatar_url,
	       c.body, c.created_at::text, c.updated_at::text,
	       (SELECT COUNT(*) FROM comment_reactions WHERE comment_id = c.id) AS reaction_count,
	       CASE WHEN $4::uuid IS NULL THEN FALSE
	            ELSE (SELECT COUNT(*) > 0 FROM comment_reactions WHERE comment_id = c.id AND user_id = $4::uuid)
	       END AS viewer_reacted
	FROM comments c
	JOIN users u ON u.id = c.author_id`

type commentRow struct {
	ID             string  `json:"id"`
	PostID         string  `json:"post_id"`
	ParentID       *string `json:"parent_id"`
	AuthorID       string  `json:"author_id"`
	AuthorUsername string  `json:"author_username"`
	AuthorName     string  `json:"author_display_name"`
	AuthorAvatar   *string `json:"author_avatar_url"`
	Body           string  `json:"body"`
	CreatedAt      string  `json:"created_at"`
	UpdatedAt      string  `json:"updated_at"`
	ReactionCount  int     `json:"reaction_count"`
	ViewerReacted  bool    `json:"viewer_reacted"`
}

type commentListResponse struct {
	Comments []commentRow `json:"comments"`
	Count    int          `json:"count"`
	Total    int          `json:"total"`
	HasMore  bool         `json:"has_more"`
}

func ListComments(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		postID := r.PathValue("id")
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)

		// Resolve optional viewer ID for viewer_reacted column.
		var viewerID *string
		if claims := middleware.ClaimsFrom(r.Context()); claims != nil {
			var uid string
			if err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&uid); err == nil {
				viewerID = &uid
			}
		}

		// Fetch total comment count for this post (used for has_more / UI display).
		var total int
		_ = d.Pool.QueryRow(r.Context(), `SELECT COUNT(*) FROM comments WHERE post_id = $1`, postID).Scan(&total)

		orderBy := "c.created_at DESC"
		switch r.URL.Query().Get("sort") {
		case "oldest":
			orderBy = "c.created_at ASC"
		case "top":
			orderBy = "(SELECT COUNT(*) FROM comment_reactions cr WHERE cr.comment_id = c.id) DESC, c.created_at DESC"
		}

		rows, err := d.Pool.Query(r.Context(), fmt.Sprintf(commentSelectSQL+`
			WHERE c.post_id = $1
			ORDER BY %s
			LIMIT $2 OFFSET $3`, orderBy), postID, limit, offset, viewerID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var comments []commentRow
		for rows.Next() {
			var c commentRow
			if err := rows.Scan(
				&c.ID, &c.PostID, &c.ParentID, &c.AuthorID,
				&c.AuthorUsername, &c.AuthorName, &c.AuthorAvatar,
				&c.Body, &c.CreatedAt, &c.UpdatedAt,
				&c.ReactionCount, &c.ViewerReacted,
			); err != nil {
				continue
			}
			comments = append(comments, c)
		}
		if comments == nil {
			comments = []commentRow{}
		}
		hasMore := offset+len(comments) < total
		writeJSON(w, http.StatusOK, commentListResponse{
			Comments: comments,
			Count:    len(comments),
			Total:    total,
			HasMore:  hasMore,
		})
	}
}

func CreateComment(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		postID := r.PathValue("id")

		var req struct {
			Body     string  `json:"body"`
			ParentID *string `json:"parent_id"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if strings.TrimSpace(req.Body) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body is required"})
			return
		}

		var userID string
		err := d.Pool.QueryRow(r.Context(), `SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		// Validate parent_id and flatten to one level of nesting.
		var resolvedParentID *string
		if req.ParentID != nil && *req.ParentID != "" {
			var parentPostID string
			var grandparentID *string
			err := d.Pool.QueryRow(r.Context(),
				`SELECT post_id, parent_id FROM comments WHERE id=$1`, *req.ParentID,
			).Scan(&parentPostID, &grandparentID)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parent comment not found"})
				return
			}
			if parentPostID != postID {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parent comment does not belong to this post"})
				return
			}
			// Flatten: if the parent itself is a reply, use its parent id instead.
			if grandparentID != nil {
				resolvedParentID = grandparentID
			} else {
				resolvedParentID = req.ParentID
			}
		}

		var id string
		err = d.Pool.QueryRow(r.Context(),
			`INSERT INTO comments (post_id, parent_id, author_id, body) VALUES ($1,$2,$3,$4) RETURNING id`,
			postID, resolvedParentID, userID, strings.TrimSpace(req.Body),
		).Scan(&id)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}

		var postAuthorID string
		if err := d.Pool.QueryRow(r.Context(), `SELECT author_id FROM posts WHERE id=$1`, postID).Scan(&postAuthorID); err == nil {
			createNotification(r.Context(), d.Pool, d.Cfg, postAuthorID, userID, "comment_on_post", &postID, &id)
			if postAuthorID != userID {
				go func(recipientID, pid string) {
					if d.Mailer != nil {
						sendCommentEmail(d.Pool, d.Mailer, recipientID, claims.Sub, pid)
						var slug, title string
						if err := d.Pool.QueryRow(context.Background(), `SELECT slug, title FROM posts WHERE id=$1`, pid).Scan(&slug, &title); err == nil {
							notifications.SendCommentEmail(context.Background(), d.Pool, d.Mailer, d.Cfg, claims.Sub, recipientID, slug, title, strings.TrimSpace(req.Body))
						}
					}
				}(postAuthorID, postID)
			}
		}

		// Notify post subscribers (excluding commenter and post author who's already notified above)
		subRows, subErr := d.Pool.Query(r.Context(), `
			SELECT ps.user_id FROM post_subscriptions ps
			JOIN users u ON u.id = ps.user_id
			WHERE ps.post_id = $1 AND u.username != $2`,
			postID, claims.Sub)
		if subErr == nil {
			defer subRows.Close()
			for subRows.Next() {
				var subUserID string
				if err := subRows.Scan(&subUserID); err != nil {
					continue
				}
				// skip if this subscriber is also the post author (already notified above)
				if subUserID == postAuthorID {
					continue
				}
				d.Pool.Exec(r.Context(), `
					INSERT INTO notifications (user_id, actor_id, type, post_id, comment_id)
					VALUES ($1, $2, 'comment_on_post', $3, $4)`,
					subUserID, userID, postID, id)
			}
		}

		// Fire mention notifications for any @username found in the comment body.
		go func() {
			usernames := mentions.Extract(strings.TrimSpace(req.Body))
			if len(usernames) > 0 {
				mentions.NotifyMentions(context.Background(), d.Pool, userID, usernames, postID, id)
			}
		}()

		writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	}
}

// sendCommentEmail fetches recipient and post details then sends a new-comment email.
func sendCommentEmail(pool *pgxpool.Pool, mailer *email.Mailer, recipientID, actorUsername, postID string) {
	ctx := context.Background()
	var toAddr, toUsername, postTitle, postSlug string
	if err := pool.QueryRow(ctx, `SELECT email, username FROM users WHERE id=$1`, recipientID).Scan(&toAddr, &toUsername); err != nil || toAddr == "" {
		return
	}
	if err := pool.QueryRow(ctx, `SELECT title, slug FROM posts WHERE id=$1`, postID).Scan(&postTitle, &postSlug); err != nil {
		return
	}
	_ = mailer.SendNewComment(toAddr, toUsername, actorUsername, postTitle, postSlug)
}

func DeleteComment(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM comments c JOIN users u ON u.id=c.author_id WHERE c.id=$1`, id,
		).Scan(&authorUsername)
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if authorUsername != claims.Sub && !auth.HasRole(claims.Role, "moderator") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		_, _ = d.Pool.Exec(r.Context(), `DELETE FROM comments WHERE id=$1`, id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func UpdateComment(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var req struct {
			Body string `json:"body"`
		}
		if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Body) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body is required"})
			return
		}

		var authorUsername string
		err := d.Pool.QueryRow(r.Context(),
			`SELECT u.username FROM comments c JOIN users u ON u.id=c.author_id WHERE c.id=$1`, id,
		).Scan(&authorUsername)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if authorUsername != claims.Sub {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		tag, err := d.Pool.Exec(r.Context(),
			`UPDATE comments SET body = $1, updated_at = now() WHERE id = $2`,
			strings.TrimSpace(req.Body), id)
		if err != nil || tag.RowsAffected() == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found or forbidden"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
