package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/api/middleware"
)

// ---------- one-time SSE tickets ----------
//
// EventSource cannot send Authorization headers, so we issue a 30-second
// opaque one-time ticket via a normal authenticated REST call. The ticket
// is stored in PostgreSQL so it is valid across all service instances.
// It is consumed (deleted) on first use and never appears in server logs again.

func issueSSETicket(ctx context.Context, pool *pgxpool.Pool, username string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(b)
	_, err := pool.Exec(ctx,
		`INSERT INTO sse_tickets (ticket, username, expires_at) VALUES ($1, $2, now() + interval '30 seconds')`,
		ticket, username,
	)
	return ticket, err
}

func consumeSSETicket(ctx context.Context, pool *pgxpool.Pool, ticket string) (string, bool) {
	var username string
	err := pool.QueryRow(ctx,
		`DELETE FROM sse_tickets WHERE ticket = $1 AND expires_at > now() RETURNING username`,
		ticket,
	).Scan(&username)
	if err != nil {
		return "", false
	}
	return username, true
}

// ---------- handlers ----------

// IssueSSETicket issues a 30-second one-time opaque ticket for the SSE stream.
// POST /api/v1/me/notifications/stream-ticket
func IssueSSETicket(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFrom(r.Context())
		if claims == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		ticket, err := issueSSETicket(r.Context(), d.Pool, claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue ticket"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"ticket": ticket})
	}
}

// NotificationStream streams unread notification counts via SSE using
// PostgreSQL LISTEN/NOTIFY — no DB polling loop.
//
// Auth: Bearer token via optAuth middleware OR a one-time ?ticket= param
// issued by IssueSSETicket (EventSource clients cannot send headers).
//
// GET /api/v1/me/notifications/stream
func NotificationStream(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var username string
		if claims := middleware.ClaimsFrom(r.Context()); claims != nil {
			username = claims.Sub
		} else {
			ticketParam := r.URL.Query().Get("ticket")
			if ticketParam == "" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var ok bool
			username, ok = consumeSSETicket(r.Context(), d.Pool, ticketParam)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Resolve username → UUID once; used for LISTEN channel and count queries.
		var userID string
		if err := d.Pool.QueryRow(r.Context(),
			`SELECT id FROM users WHERE username=$1`, username).Scan(&userID); err != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		// Channel: "notif_" + 32 hex chars (UUID without hyphens) — valid unquoted identifier.
		channel := "notif_" + strings.ReplaceAll(userID, "-", "")

		// Acquire a dedicated connection; LISTEN state is per-connection and
		// must not be shared with pool connections used for other queries.
		conn, err := d.Pool.Acquire(r.Context())
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		defer conn.Release()

		if _, err := conn.Exec(r.Context(), "LISTEN "+channel); err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		sendCount := func() {
			var c int
			d.Pool.QueryRow(r.Context(),
				`SELECT COUNT(*) FROM notifications WHERE user_id=$1 AND read=false`,
				userID).Scan(&c)
			fmt.Fprintf(w, "event: unread_count\ndata: %d\n\n", c)
			flusher.Flush()
		}

		sendCount()

		for {
			// Block up to 30 s waiting for pg_notify. Timeout → keepalive ping.
			waitCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			_, waitErr := conn.Conn().WaitForNotification(waitCtx)
			cancel()

			if r.Context().Err() != nil {
				return // client disconnected
			}
			if waitErr != nil {
				if errors.Is(waitErr, context.DeadlineExceeded) {
					fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
					flusher.Flush()
					continue
				}
				return // connection broken
			}

			sendCount()
		}
	}
}
