// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/opensecstack/community/internal/api/middleware"
)

// ToggleMessageReaction handles POST /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions
//
// Body: {"emoji": "👍"}
//
// If the viewer has already reacted with the given emoji the reaction is
// removed; otherwise it is added. Requires space membership.
func ToggleMessageReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")
		msgID := r.PathValue("id")
		userID := resolveUserID(r.Context(), d.Pool, claims.Sub)
		if userID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}

		spaceID, channelID := resolveChannel(r, d, spaceSlug, channelSlug, userID)
		if channelID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}

		// Require space membership.
		if spaceRole(r, d, spaceID, userID) == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "join the space first"})
			return
		}

		var req struct {
			Emoji string `json:"emoji"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Emoji = strings.TrimSpace(req.Emoji)
		if req.Emoji == "" || utf8.RuneCountInString(req.Emoji) > 8 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid emoji"})
			return
		}

		// Confirm the message belongs to the resolved channel.
		var exists bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM channel_messages WHERE id=$1 AND channel_id=$2)`,
			msgID, channelID).Scan(&exists)
		if !exists {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "message not found"})
			return
		}

		// Toggle: try insert first; if it already exists, delete it.
		var added bool
		var existing bool
		_ = d.Pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM channel_message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3)`,
			msgID, userID, req.Emoji).Scan(&existing)

		if existing {
			d.Pool.Exec(r.Context(), //nolint:errcheck
				`DELETE FROM channel_message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3`,
				msgID, userID, req.Emoji)
			added = false
		} else {
			d.Pool.Exec(r.Context(), //nolint:errcheck
				`INSERT INTO channel_message_reactions (message_id, user_id, emoji) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
				msgID, userID, req.Emoji)
			added = true
		}

		// Return updated reaction counts for this message.
		counts := reactionCounts(r, d, msgID)
		writeJSON(w, http.StatusOK, map[string]any{"added": added, "reactions": counts})
	}
}

// RemoveMessageReaction handles
// DELETE /api/v1/spaces/{slug}/channels/{channel}/messages/{id}/reactions/{emoji}
//
// Explicit removal of a single reaction by the authenticated viewer.
func RemoveMessageReaction(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")
		msgID := r.PathValue("id")
		emoji := r.PathValue("emoji")
		userID := resolveUserID(r.Context(), d.Pool, claims.Sub)
		if userID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}

		_, channelID := resolveChannel(r, d, spaceSlug, channelSlug, userID)
		if channelID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}

		d.Pool.Exec(r.Context(), //nolint:errcheck
			`DELETE FROM channel_message_reactions WHERE message_id=$1 AND user_id=$2 AND emoji=$3`,
			msgID, userID, emoji)

		counts := reactionCounts(r, d, msgID)
		writeJSON(w, http.StatusOK, map[string]any{"reactions": counts})
	}
}

// reactionCounts returns a map of emoji -> count for all reactions on a message.
func reactionCounts(r *http.Request, d Deps, msgID string) map[string]int {
	counts := map[string]int{}
	rows, err := d.Pool.Query(r.Context(),
		`SELECT emoji, COUNT(*) FROM channel_message_reactions WHERE message_id=$1 GROUP BY emoji`, msgID)
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var emoji string
		var cnt int
		if rows.Scan(&emoji, &cnt) == nil {
			counts[emoji] = cnt
		}
	}
	return counts
}
