// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/opensecstack/community/internal/api/middleware"
)

// messageRow is the JSON shape returned for a single channel message.
type messageRow struct {
	ID                string            `json:"id"`
	ChannelID         string            `json:"channel_id"`
	AuthorID          string            `json:"author_id"`
	AuthorUsername    string            `json:"author_username"`
	AuthorDisplayName string            `json:"author_display_name"`
	AuthorAvatarURL   *string           `json:"author_avatar_url"`
	Content           string            `json:"content"`
	EditedAt          *string           `json:"edited_at"`
	ParentID          *string           `json:"parent_id"`
	CreatedAt         string            `json:"created_at"`
	Reactions         map[string]int    `json:"reactions"`
	ViewerReacted     []string          `json:"viewer_reacted"`
	Attachments       []attachmentRow   `json:"attachments"`
}

type attachmentRow struct {
	ID       string `json:"id"`
	FileURL  string `json:"file_url"`
	FileName string `json:"file_name"`
	MimeType string `json:"mime_type"`
	FileSize int64  `json:"file_size"`
}

// resolveChannel resolves a space slug + channel slug pair into the channel UUID
// and, as a side effect, validates that the space exists and is accessible to
// the given userID (empty string = anonymous). Returns "", "" on any error.
func resolveChannel(r *http.Request, d Deps, spaceSlug, channelSlug, userID string) (spaceID, channelID string) {
	var isPrivate bool
	if err := d.Pool.QueryRow(r.Context(),
		`SELECT id, is_private FROM spaces WHERE slug=$1`, spaceSlug).
		Scan(&spaceID, &isPrivate); err != nil {
		return "", ""
	}
	if isPrivate && (userID == "" || spaceRole(r, d, spaceID, userID) == "") {
		return "", ""
	}
	if err := d.Pool.QueryRow(r.Context(),
		`SELECT id FROM channels WHERE space_id=$1 AND slug=$2`, spaceID, channelSlug).
		Scan(&channelID); err != nil {
		return "", ""
	}
	return spaceID, channelID
}

// fetchMessageByID loads a single message row (with author, reactions, attachments)
// for the given message UUID and viewer userID (empty = anonymous).
func fetchMessageByID(r *http.Request, d Deps, msgID, viewerID string) (*messageRow, error) {
	var msg messageRow
	err := d.Pool.QueryRow(r.Context(), `
		SELECT cm.id::text,
		       cm.channel_id::text,
		       cm.author_id::text,
		       u.username,
		       u.display_name,
		       u.avatar_url,
		       cm.content,
		       cm.edited_at::text,
		       cm.parent_id::text,
		       cm.created_at::text
		FROM channel_messages cm
		JOIN users u ON u.id = cm.author_id
		WHERE cm.id = $1`, msgID).
		Scan(&msg.ID, &msg.ChannelID, &msg.AuthorID,
			&msg.AuthorUsername, &msg.AuthorDisplayName, &msg.AuthorAvatarURL,
			&msg.Content, &msg.EditedAt, &msg.ParentID, &msg.CreatedAt)
	if err != nil {
		return nil, err
	}

	msg.Reactions = map[string]int{}
	msg.ViewerReacted = []string{}
	msg.Attachments = []attachmentRow{}

	// Reaction counts
	rRows, err := d.Pool.Query(r.Context(),
		`SELECT emoji, COUNT(*) FROM channel_message_reactions WHERE message_id=$1 GROUP BY emoji`, msgID)
	if err == nil {
		defer rRows.Close()
		for rRows.Next() {
			var emoji string
			var cnt int
			if rRows.Scan(&emoji, &cnt) == nil {
				msg.Reactions[emoji] = cnt
			}
		}
	}

	// Emojis the viewer already reacted with
	if viewerID != "" {
		vrRows, err := d.Pool.Query(r.Context(),
			`SELECT emoji FROM channel_message_reactions WHERE message_id=$1 AND user_id=$2`, msgID, viewerID)
		if err == nil {
			defer vrRows.Close()
			for vrRows.Next() {
				var emoji string
				if vrRows.Scan(&emoji) == nil {
					msg.ViewerReacted = append(msg.ViewerReacted, emoji)
				}
			}
		}
	}

	// Attachments
	aRows, err := d.Pool.Query(r.Context(),
		`SELECT id::text, file_url, file_name, mime_type, file_size
		 FROM channel_message_attachments WHERE message_id=$1 ORDER BY created_at`, msgID)
	if err == nil {
		defer aRows.Close()
		for aRows.Next() {
			var a attachmentRow
			if aRows.Scan(&a.ID, &a.FileURL, &a.FileName, &a.MimeType, &a.FileSize) == nil {
				msg.Attachments = append(msg.Attachments, a)
			}
		}
	}

	return &msg, nil
}

// ListChannelMessages handles GET /api/v1/spaces/{slug}/channels/{channel}/messages
//
// Supports cursor-based pagination via the `before` query param (a message UUID)
// and a `limit` param (default 50, max 100). Returns messages in descending
// created_at order so the client reverses them for display.
func ListChannelMessages(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")
		claims := middleware.ClaimsFrom(r.Context())

		var viewerID string
		if claims != nil {
			viewerID = resolveUserID(r.Context(), d.Pool, claims.Sub)
		}

		_, channelID := resolveChannel(r, d, spaceSlug, channelSlug, viewerID)
		if channelID == "" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}

		limit := queryInt(r, "limit", 50)
		if limit > 100 {
			limit = 100
		}
		before := strings.TrimSpace(r.URL.Query().Get("before"))

		// Fetch one extra row to determine has_more.
		var rows interface{ Close() }
		var err error
		if before != "" {
			rows, err = d.Pool.Query(r.Context(), `
				SELECT cm.id::text,
				       cm.channel_id::text,
				       cm.author_id::text,
				       u.username,
				       u.display_name,
				       u.avatar_url,
				       cm.content,
				       cm.edited_at::text,
				       cm.parent_id::text,
				       cm.created_at::text
				FROM channel_messages cm
				JOIN users u ON u.id = cm.author_id
				WHERE cm.channel_id = $1
				  AND cm.created_at < (
				      SELECT created_at FROM channel_messages WHERE id = $2::uuid
				  )
				ORDER BY cm.created_at DESC
				LIMIT $3`, channelID, before, limit+1)
		} else {
			rows, err = d.Pool.Query(r.Context(), `
				SELECT cm.id::text,
				       cm.channel_id::text,
				       cm.author_id::text,
				       u.username,
				       u.display_name,
				       u.avatar_url,
				       cm.content,
				       cm.edited_at::text,
				       cm.parent_id::text,
				       cm.created_at::text
				FROM channel_messages cm
				JOIN users u ON u.id = cm.author_id
				WHERE cm.channel_id = $1
				ORDER BY cm.created_at DESC
				LIMIT $2`, channelID, limit+1)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		// Use the concrete pgx rows type to be able to call Next/Scan.
		type pgxRows interface {
			Next() bool
			Scan(...any) error
			Close()
		}
		pgRows := rows.(pgxRows)
		defer pgRows.Close()

		msgs := []messageRow{}
		for pgRows.Next() {
			var msg messageRow
			if err := pgRows.Scan(
				&msg.ID, &msg.ChannelID, &msg.AuthorID,
				&msg.AuthorUsername, &msg.AuthorDisplayName, &msg.AuthorAvatarURL,
				&msg.Content, &msg.EditedAt, &msg.ParentID, &msg.CreatedAt,
			); err != nil {
				continue
			}
			msg.Reactions = map[string]int{}
			msg.ViewerReacted = []string{}
			msg.Attachments = []attachmentRow{}
			msgs = append(msgs, msg)
		}

		hasMore := false
		if len(msgs) > limit {
			hasMore = true
			msgs = msgs[:limit]
		}

		// Enrich each message with reactions and attachments.
		msgIDs := make([]string, len(msgs))
		for i := range msgs {
			msgIDs[i] = msgs[i].ID
		}
		enrichMessages(r, d, msgs, viewerID)

		writeJSON(w, http.StatusOK, map[string]any{
			"messages": msgs,
			"has_more": hasMore,
		})
	}
}

// enrichMessages loads reactions and attachments for a batch of messages in-place.
func enrichMessages(r *http.Request, d Deps, msgs []messageRow, viewerID string) {
	for i := range msgs {
		msgID := msgs[i].ID

		// Reaction counts
		rRows, err := d.Pool.Query(r.Context(),
			`SELECT emoji, COUNT(*) FROM channel_message_reactions WHERE message_id=$1 GROUP BY emoji`, msgID)
		if err == nil {
			for rRows.Next() {
				var emoji string
				var cnt int
				if rRows.Scan(&emoji, &cnt) == nil {
					msgs[i].Reactions[emoji] = cnt
				}
			}
			rRows.Close()
		}

		// Viewer reacted
		if viewerID != "" {
			vrRows, err := d.Pool.Query(r.Context(),
				`SELECT emoji FROM channel_message_reactions WHERE message_id=$1 AND user_id=$2`, msgID, viewerID)
			if err == nil {
				for vrRows.Next() {
					var emoji string
					if vrRows.Scan(&emoji) == nil {
						msgs[i].ViewerReacted = append(msgs[i].ViewerReacted, emoji)
					}
				}
				vrRows.Close()
			}
		}

		// Attachments
		aRows, err := d.Pool.Query(r.Context(),
			`SELECT id::text, file_url, file_name, mime_type, file_size
			 FROM channel_message_attachments WHERE message_id=$1 ORDER BY created_at`, msgID)
		if err == nil {
			for aRows.Next() {
				var a attachmentRow
				if aRows.Scan(&a.ID, &a.FileURL, &a.FileName, &a.MimeType, &a.FileSize) == nil {
					msgs[i].Attachments = append(msgs[i].Attachments, a)
				}
			}
			aRows.Close()
		}
	}
}

// CreateChannelMessage handles POST /api/v1/spaces/{slug}/channels/{channel}/messages
func CreateChannelMessage(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")
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
			Content  string  `json:"content"`
			ParentID *string `json:"parent_id"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Content = strings.TrimSpace(req.Content)
		if req.Content == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content is required"})
			return
		}

		var msgID string
		err := d.Pool.QueryRow(r.Context(), `
			INSERT INTO channel_messages (channel_id, author_id, content, parent_id)
			VALUES ($1, $2, $3, $4)
			RETURNING id::text`,
			channelID, userID, req.Content, req.ParentID).Scan(&msgID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		msg, err := fetchMessageByID(r, d, msgID, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		// Publish to the channel hub for real-time delivery.
		if d.ChannelHub != nil {
			if payload, err := json.Marshal(msg); err == nil {
				d.ChannelHub.Publish(channelID, payload)
			}
		}

		writeJSON(w, http.StatusCreated, msg)
	}
}

// EditChannelMessage handles PUT /api/v1/spaces/{slug}/channels/{channel}/messages/{id}
//
// Only the original author or a space moderator/owner may edit a message.
func EditChannelMessage(d Deps) http.HandlerFunc {
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

		// Load the message to verify ownership.
		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT author_id::text FROM channel_messages WHERE id=$1 AND channel_id=$2`,
			msgID, channelID).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "message not found"})
			return
		}

		role := spaceRole(r, d, spaceID, userID)
		if authorID != userID && role != "owner" && role != "moderator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		var req struct {
			Content string `json:"content"`
		}
		if err := decodeJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req.Content = strings.TrimSpace(req.Content)
		if req.Content == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content is required"})
			return
		}

		if _, err := d.Pool.Exec(r.Context(),
			`UPDATE channel_messages SET content=$1, edited_at=NOW() WHERE id=$2`,
			req.Content, msgID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}

		msg, err := fetchMessageByID(r, d, msgID, userID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		writeJSON(w, http.StatusOK, msg)
	}
}

// DeleteChannelMessage handles DELETE /api/v1/spaces/{slug}/channels/{channel}/messages/{id}
//
// Only the original author or a space moderator/owner may delete a message.
func DeleteChannelMessage(d Deps) http.HandlerFunc {
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

		// Load the message to verify ownership.
		var authorID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT author_id::text FROM channel_messages WHERE id=$1 AND channel_id=$2`,
			msgID, channelID).Scan(&authorID); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "message not found"})
			return
		}

		role := spaceRole(r, d, spaceID, userID)
		if authorID != userID && role != "owner" && role != "moderator" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}

		if _, err := d.Pool.Exec(r.Context(),
			`DELETE FROM channel_messages WHERE id=$1`, msgID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
