package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestIssueSSETicket_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/stream-ticket", nil)
	w := httptest.NewRecorder()

	handlers.IssueSSETicket(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIssueSSETicket_Success(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "sse_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, username)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/stream-ticket", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.IssueSSETicket(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["ticket"] == "" {
		t.Fatal("expected a non-empty ticket")
	}

	var storedUsername string
	if err := pool.QueryRow(context.Background(),
		`SELECT username FROM sse_tickets WHERE ticket=$1`, resp["ticket"],
	).Scan(&storedUsername); err != nil {
		t.Fatalf("query ticket: %v", err)
	}
	if storedUsername != username {
		t.Errorf("expected stored username %q, got %q", username, storedUsername)
	}
}

func TestNotificationStream_NoAuth_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream", nil)
	w := httptest.NewRecorder()

	handlers.NotificationStream(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with neither claims nor ticket, got %d", w.Code)
	}
}

func TestNotificationStream_InvalidTicket_Returns401(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream?ticket=bogus-"+handlers.RandomSuffix(), nil)
	w := httptest.NewRecorder()

	handlers.NotificationStream(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an invalid ticket, got %d", w.Code)
	}
}

func TestNotificationStream_ClaimsUserNotFound_Returns404(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream", nil)
	req = withClaims(req, &auth.Claims{Sub: "no-such-user-" + handlers.RandomSuffix(), Role: "author"})
	w := httptest.NewRecorder()

	handlers.NotificationStream(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when the claimed user does not exist, got %d", w.Code)
	}
}

// nonFlushingRecorder wraps httptest.ResponseRecorder via a named (not
// embedded) field so Flush is not promoted — it does not satisfy
// http.Flusher, exercising NotificationStream's "streaming unsupported"
// branch.
type nonFlushingRecorder struct {
	rec *httptest.ResponseRecorder
}

func (n *nonFlushingRecorder) Header() http.Header         { return n.rec.Header() }
func (n *nonFlushingRecorder) Write(b []byte) (int, error) { return n.rec.Write(b) }
func (n *nonFlushingRecorder) WriteHeader(code int)        { n.rec.WriteHeader(code) }

func TestNotificationStream_StreamingUnsupported_Returns500(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "sse_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, username)

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := &nonFlushingRecorder{rec: httptest.NewRecorder()}

	handlers.NotificationStream(d)(w, req)

	if w.rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when the ResponseWriter doesn't support flushing, got %d", w.rec.Code)
	}
}

func TestNotificationStream_ClaimsSuccess_StreamsInitialCount(t *testing.T) {
	pool := handlers.NewTestDBPool(t)
	d := handlers.Deps{Pool: pool}
	username := "sse_" + handlers.RandomSuffix()
	handlers.CleanupUserByUsername(t, pool, username)

	if _, err := pool.Exec(context.Background(), `INSERT INTO users (username) VALUES ($1)`, username); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications/stream", nil).WithContext(ctx)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handlers.NotificationStream(d)(w, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("NotificationStream did not return after client context cancellation")
	}

	if body := w.Body.String(); !strings.Contains(body, "event: unread_count") {
		t.Errorf("expected an initial 'unread_count' SSE event, got body: %q", body)
	}
}
