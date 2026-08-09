package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// These tests exercise the real TaranisWebhookHandler / TaranisClient types
// (as opposed to the duplicated stub handler above) on code paths that
// return before ever touching the *db.IncidentStore field, so a nil store
// is safe: a panic here would mean the early-return no longer short-circuits.

func TestTaranisWebhookHandler_ServeHTTP_InvalidHMACReturns401(t *testing.T) {
	h := NewTaranisWebhookHandler([]byte("secret"), nil, zerolog.Nop())
	payload := []byte(`[{"id":"t1","title":"x"}]`)
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(payload)))
	req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
	req.Header.Set("X-Signature", "not-a-valid-signature")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rr.Code)
	}
}

func TestTaranisWebhookHandler_ServeHTTP_InvalidJSONReturns400(t *testing.T) {
	// No secret configured -> HMAC check skipped, so we reach JSON parsing.
	h := NewTaranisWebhookHandler(nil, nil, zerolog.Nop())
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{not json"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rr.Code)
	}
}

func TestTaranisWebhookHandler_ServeHTTP_EmptyArrayReturns200WithoutTouchingStore(t *testing.T) {
	h := NewTaranisWebhookHandler(nil, nil, zerolog.Nop())
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("[]"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
}

func TestNewTaranisClient_SetsFields(t *testing.T) {
	c := NewTaranisClient("http://example.invalid", "key", 5*time.Minute, nil, zerolog.Nop())
	if c == nil {
		t.Fatal("NewTaranisClient returned nil")
	}
	if c.apiURL != "http://example.invalid" {
		t.Errorf("apiURL = %q", c.apiURL)
	}
	if c.apiKey != "key" {
		t.Errorf("apiKey = %q", c.apiKey)
	}
	if c.interval != 5*time.Minute {
		t.Errorf("interval = %v", c.interval)
	}
	if c.http == nil {
		t.Error("http client should be initialized")
	}
}

func TestTaranisClient_CursorRoundTrip(t *testing.T) {
	c := NewTaranisClient("http://example.invalid", "", time.Minute, nil, zerolog.Nop())
	if got := c.loadCursor(); got != "" {
		t.Fatalf("initial cursor = %q, want empty", got)
	}
	c.storeCursor("cursor-123")
	if got := c.loadCursor(); got != "cursor-123" {
		t.Fatalf("loadCursor after store = %q, want cursor-123", got)
	}
}

func TestTaranisClient_Run_EmptyAPIURLReturnsImmediately(t *testing.T) {
	c := NewTaranisClient("", "", time.Millisecond, nil, zerolog.Nop())
	done := make(chan struct{})
	go func() {
		c.Run(context.Background())
		close(done)
	}()
	select {
	case <-done:
		// expected: Run must return immediately when apiURL is empty,
		// without ever ticking (which would call pollOnce and panic on
		// the nil incidents store).
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly for empty apiURL")
	}
}

func TestTaranisClient_PollOnce_UpstreamErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewTaranisClient(srv.URL, "", time.Minute, nil, zerolog.Nop())
	if err := c.pollOnce(context.Background()); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestTaranisClient_PollOnce_InvalidJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	c := NewTaranisClient(srv.URL, "", time.Minute, nil, zerolog.Nop())
	if err := c.pollOnce(context.Background()); err == nil {
		t.Fatal("expected decode error for invalid JSON body")
	}
}

func TestTaranisClient_PollOnce_ForwardsCursorAndAPIKey(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := NewTaranisClient(srv.URL, "my-key", time.Minute, nil, zerolog.Nop())
	c.storeCursor("abc")
	if err := c.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if gotAuth != "Bearer my-key" {
		t.Errorf("Authorization = %q, want Bearer my-key", gotAuth)
	}
	if !strings.Contains(gotQuery, "after=abc") {
		t.Errorf("query = %q, want it to contain after=abc", gotQuery)
	}
}
