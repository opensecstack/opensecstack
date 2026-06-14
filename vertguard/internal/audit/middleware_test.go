package audit

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

func newTestRouter(sink Sink, hook MetricsHook, status int) http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	logger := zerolog.New(io.Discard)
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(Middleware(sink, &logger, hook))
		r.Post("/things/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		r.Get("/things/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		r.Delete("/things/{id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
	})
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})
	return r
}

type counterHook struct{ outcomes []string }

func (c *counterHook) IncAuditEvent(o string) { c.outcomes = append(c.outcomes, o) }

func TestMiddleware_AuditMatrix(t *testing.T) {
	cases := []struct {
		name        string
		method      string
		path        string
		status      int
		wantEvents  int
		wantOutcome string
		wantAction  string
	}{
		{"POST 2xx → success", http.MethodPost, "/api/v1/things/42", 201, 1, OutcomeSuccess, "POST /api/v1/things/{id}"},
		{"POST 4xx → denied", http.MethodPost, "/api/v1/things/42", 403, 1, OutcomeDenied, "POST /api/v1/things/{id}"},
		{"POST 5xx → error", http.MethodPost, "/api/v1/things/42", 500, 1, OutcomeError, "POST /api/v1/things/{id}"},
		{"DELETE 2xx → success", http.MethodDelete, "/api/v1/things/42", 204, 1, OutcomeSuccess, "DELETE /api/v1/things/{id}"},
		{"GET skipped", http.MethodGet, "/api/v1/things/42", 200, 0, "", ""},
		{"non-/api/v1 skipped", http.MethodGet, "/health", 200, 0, "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &fakeSink{}
			hook := &counterHook{}
			h := newTestRouter(sink, hook, tc.status)

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = "10.0.0.1:5555"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if got := sink.calls(); got != tc.wantEvents {
				t.Fatalf("events: got %d, want %d", got, tc.wantEvents)
			}
			if tc.wantEvents == 0 {
				if len(hook.outcomes) != 0 {
					t.Fatalf("metric hook fired on skipped request: %v", hook.outcomes)
				}
				return
			}
			ev := sink.events[0]
			if ev.Outcome != tc.wantOutcome {
				t.Errorf("outcome=%q want %q", ev.Outcome, tc.wantOutcome)
			}
			if ev.Action != tc.wantAction {
				t.Errorf("action=%q want %q", ev.Action, tc.wantAction)
			}
			if ev.StatusCode != tc.status {
				t.Errorf("status=%d want %d", ev.StatusCode, tc.status)
			}
			if ev.Actor != "anonymous" {
				t.Errorf("actor=%q want anonymous (no claims in ctx)", ev.Actor)
			}
			if ev.RemoteIP != "10.0.0.1" {
				t.Errorf("remote_ip=%q want 10.0.0.1", ev.RemoteIP)
			}
			if ev.RequestID == "" {
				t.Errorf("request_id should be set by chi RequestID middleware")
			}
			if len(hook.outcomes) != 1 || hook.outcomes[0] != tc.wantOutcome {
				t.Errorf("metric hook outcomes=%v", hook.outcomes)
			}
		})
	}
}

func TestMiddleware_NilSinkSafe(t *testing.T) {
	h := newTestRouter(nil, nil, 200)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/things/1", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
}
