// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
)

// StreamChannelMessages handles SSE for real-time channel message events.
// Route: GET /api/v1/spaces/{slug}/channels/{channel}/stream
// Requires auth + space membership (or the space must be public).
func StreamChannelMessages(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.ChannelHub == nil {
			http.Error(w, "streaming not available", http.StatusServiceUnavailable)
			return
		}

		// Auth: standard Bearer token via middleware, or ?token= fallback for
		// EventSource clients that cannot send custom headers.
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			tokenParam := r.URL.Query().Get("token")
			if tokenParam == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var err error
			claims, err = auth.Verify(tokenParam, d.Cfg.JWTSecret)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		spaceSlug := r.PathValue("slug")
		channelSlug := r.PathValue("channel")

		// Resolve caller's user ID (may be empty for unauthenticated check paths,
		// but claims are guaranteed above, so it will be set).
		userID := getUID(r, d, claims.Sub)

		// Resolve space and enforce access.
		var spaceID string
		var isPrivate bool
		err := d.Pool.QueryRow(r.Context(),
			`SELECT id, is_private FROM spaces WHERE slug=$1`, spaceSlug).
			Scan(&spaceID, &isPrivate)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "space not found"})
			return
		}
		if isPrivate && (userID == "" || spaceRole(r, d, spaceID, userID) == "") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "private space"})
			return
		}

		// Resolve channel ID from space + channel slug.
		var channelID string
		err = d.Pool.QueryRow(r.Context(),
			`SELECT id FROM channels WHERE space_id=$1 AND slug=$2`, spaceID, channelSlug).
			Scan(&channelID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "channel not found"})
			return
		}

		// Set SSE headers before writing any body.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		// Send an initial ping so the client knows the connection is live.
		fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
		flusher.Flush()

		ch := d.ChannelHub.Subscribe(channelID)
		defer d.ChannelHub.Unsubscribe(channelID, ch)

		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case payload, ok := <-ch:
				if !ok {
					return
				}
				fmt.Fprintf(w, "data: %s\n\n", payload)
				flusher.Flush()
			case <-ticker.C:
				// Keepalive comment to prevent proxy/browser timeouts.
				fmt.Fprintf(w, ":\n\n")
				flusher.Flush()
			}
		}
	}
}
