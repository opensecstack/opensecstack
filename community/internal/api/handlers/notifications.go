package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
)

type notificationRow struct {
	ID            string    `json:"id"`
	Type          string    `json:"type"`
	PostID        *string   `json:"post_id"`
	CommentID     *string   `json:"comment_id"`
	Read          bool      `json:"read"`
	CreatedAt     time.Time `json:"created_at"`
	ActorUsername *string   `json:"actor_username"`
	ActorName     *string   `json:"actor_name"`
	ActorAvatar   *string   `json:"actor_avatar"`
	PostTitle     *string   `json:"post_title"`
	PostSlug      *string   `json:"post_slug"`
	SpaceID       *string   `json:"space_id"`
	SpaceSlug     *string   `json:"space_slug"`
	SpaceName     *string   `json:"space_name"`
}

type notificationListResponse struct {
	Notifications []notificationRow `json:"notifications"`
	Count         int               `json:"count"`
	UnreadCount   int               `json:"unread_count"`
	NextCursor    *string           `json:"next_cursor"`
}

// encodeCursor returns a base64url-encoded cursor from a timestamp and row ID.
func encodeCursor(t time.Time, id string) string {
	s := fmt.Sprintf("%d_%s", t.UnixNano(), id)
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// decodeCursor parses a cursor produced by encodeCursor.
func decodeCursor(cursor string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(b), "_", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("invalid cursor")
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, "", err
	}
	return time.Unix(0, ns), parts[1], nil
}

func ListNotifications(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		limit := queryInt(r, "limit", 20)
		cursorParam := r.URL.Query().Get("cursor")

		const baseQuery = `
			SELECT n.id, n.type, n.post_id, n.comment_id, n.read, n.created_at,
			       u.username, u.display_name, u.avatar_url,
			       p.title, p.slug,
			       n.space_id, s.slug, s.name
			FROM notifications n
			LEFT JOIN users u ON u.id = n.actor_id
			LEFT JOIN posts p ON p.id = n.post_id
			LEFT JOIN spaces s ON s.id = n.space_id
			WHERE n.user_id = $1`

		var (
			query string
			args  []any
		)

		if cursorParam == "" {
			query = baseQuery + ` ORDER BY n.created_at DESC, n.id DESC LIMIT $2`
			args = []any{userID, limit}
		} else {
			cursorTime, cursorID, err := decodeCursor(cursorParam)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid cursor"})
				return
			}
			query = baseQuery + ` AND (n.created_at, n.id::text) < ($2, $3)
				ORDER BY n.created_at DESC, n.id DESC LIMIT $4`
			args = []any{userID, cursorTime, cursorID, limit}
		}

		rows, err := d.Pool.Query(r.Context(), query, args...)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		var notifications []notificationRow
		for rows.Next() {
			var n notificationRow
			if err := rows.Scan(
				&n.ID, &n.Type, &n.PostID, &n.CommentID, &n.Read, &n.CreatedAt,
				&n.ActorUsername, &n.ActorName, &n.ActorAvatar,
				&n.PostTitle, &n.PostSlug,
				&n.SpaceID, &n.SpaceSlug, &n.SpaceName,
			); err != nil {
				continue
			}
			notifications = append(notifications, n)
		}
		if notifications == nil {
			notifications = []notificationRow{}
		}

		var unreadCount int
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false`, userID,
		).Scan(&unreadCount)

		// Build next_cursor from the last returned row if we filled the page.
		var nextCursor *string
		if len(notifications) == limit {
			last := notifications[len(notifications)-1]
			c := encodeCursor(last.CreatedAt, last.ID)
			nextCursor = &c
		}

		writeJSON(w, http.StatusOK, notificationListResponse{
			Notifications: notifications,
			Count:         len(notifications),
			UnreadCount:   unreadCount,
			NextCursor:    nextCursor,
		})
	}
}

func MarkNotificationRead(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		id := r.PathValue("id")

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE notifications SET read=true WHERE id=$1 AND user_id=$2`, id, userID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func MarkAllNotificationsRead(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, claims.Sub).Scan(&userID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}

		_, _ = d.Pool.Exec(r.Context(),
			`UPDATE notifications SET read=true WHERE user_id=$1 AND read=false`, userID)
		w.WriteHeader(http.StatusNoContent)
	}
}
