package handlers

import (
	"net/http"

	"github.com/opensecstack/community/internal/api/middleware"
)

// GetSpaceUnreadCounts returns a map of channel slug → unread message count
// for channels the authenticated user has not yet read.
// GET /api/v1/spaces/{slug}/unread
func GetSpaceUnreadCounts(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		slug := r.PathValue("slug")
		userID := getUID(r, d, claims.Sub)

		var spaceID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM spaces WHERE slug=$1`, slug,
		).Scan(&spaceID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}

		rows, err := d.Pool.Query(r.Context(), `
			SELECT c.slug, COUNT(cm.id)::int
			FROM channel_messages cm
			JOIN channels c ON c.id = cm.channel_id
			WHERE c.space_id = $1
			  AND cm.author_id != $2
			  AND cm.created_at > COALESCE(
			    (SELECT clr.last_read_at FROM channel_last_read clr
			     WHERE clr.user_id = $2 AND clr.channel_id = cm.channel_id),
			    '1970-01-01'::timestamptz
			  )
			GROUP BY c.id, c.slug
		`, spaceID, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer rows.Close()

		counts := map[string]int{}
		for rows.Next() {
			var channelSlug string
			var count int
			if err := rows.Scan(&channelSlug, &count); err != nil {
				continue
			}
			if count > 0 {
				counts[channelSlug] = count
			}
		}
		writeJSON(w, http.StatusOK, counts)
	}
}

// MarkChannelRead records that the authenticated user has read up to now in a channel.
// POST /api/v1/spaces/{slug}/channels/{channel}/read
func MarkChannelRead(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")
		userID := getUID(r, d, claims.Sub)

		var channelID string
		if err := d.Pool.QueryRow(r.Context(), `
			SELECT c.id FROM channels c
			JOIN spaces s ON s.id = c.space_id
			WHERE s.slug = $1 AND c.slug = $2
		`, spaceSlug, channelSlug).Scan(&channelID); err != nil {
			// Unknown channel — silently succeed (idempotent).
			w.WriteHeader(http.StatusNoContent)
			return
		}

		_, _ = d.Pool.Exec(r.Context(), `
			INSERT INTO channel_last_read (user_id, channel_id, last_read_at)
			VALUES ($1, $2, now())
			ON CONFLICT (user_id, channel_id) DO UPDATE SET last_read_at = now()
		`, userID, channelID)
		w.WriteHeader(http.StatusNoContent)
	}
}
