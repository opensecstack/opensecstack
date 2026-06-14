package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
)

type captureSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (c *captureSink) Record(_ context.Context, e audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureSink) Events() []audit.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]audit.Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestRecoveryMiddleware(t *testing.T) {
	tests := []struct {
		name  string
		panic any
	}{
		{"string panic", "boom"},
		{"error panic", errors.New("kaboom")},
		// nil panic recovers as nil — Go runtime treats it as no panic
		// in newer versions; keep as a smoke test that the handler still
		// returns cleanly.
		{"int panic", 42},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureSink{}
			logger := zerolog.New(io.Discard)
			h := RecoveryMiddleware(sink, &logger)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
				panic(tc.panic)
			}))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/explode", nil)
			rw := httptest.NewRecorder()
			h.ServeHTTP(rw, req)

			if rw.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rw.Code)
			}
			if len(sink.Events()) != 1 {
				t.Fatalf("events = %d, want 1", len(sink.Events()))
			}
			ev := sink.Events()[0]
			if ev.Outcome != audit.OutcomeError {
				t.Fatalf("outcome = %q, want error", ev.Outcome)
			}
			if ev.StatusCode != http.StatusInternalServerError {
				t.Fatalf("status_code = %d, want 500", ev.StatusCode)
			}
			if len(ev.Metadata) == 0 {
				t.Fatalf("metadata empty, want panic+stack")
			}
		})
	}
}

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	sink := &captureSink{}
	logger := zerolog.New(io.Discard)
	h := RecoveryMiddleware(sink, &logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ok", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rw.Code)
	}
	if len(sink.Events()) != 0 {
		t.Fatalf("expected no audit events, got %d", len(sink.Events()))
	}
}
