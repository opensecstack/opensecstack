package integrations

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestVertGuardSubscriber_PullOnce_DeduplicatesAndInvokesCallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q, want Bearer test-key", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"advisories":[{"id":"adv-1","payload":{"threat":"prompt_injection"}}]}`))
	}))
	defer srv.Close()

	var calls []string
	onAdvisory := func(ctx context.Context, id string, payload map[string]any) error {
		calls = append(calls, id)
		if payload["threat"] != "prompt_injection" {
			t.Errorf("payload = %v, missing threat field", payload)
		}
		return nil
	}

	s := NewVertGuardSubscriber(srv.URL, "test-key", onAdvisory, zerolog.Nop())
	if err := s.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce: %v", err)
	}
	if len(calls) != 1 || calls[0] != "adv-1" {
		t.Fatalf("calls = %v, want [adv-1]", calls)
	}

	// Second pull returns the same advisory id — must be deduplicated.
	if err := s.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce (2nd): %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls after 2nd pull = %v, want dedup to keep it at 1 entry", calls)
	}
}

func TestVertGuardSubscriber_PullOnce_UnauthorizedIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	s := NewVertGuardSubscriber(srv.URL, "bad-key", nil, zerolog.Nop())
	if err := s.pullOnce(context.Background()); err == nil {
		t.Fatal("expected error for 401 response")
	}
}

func TestVertGuardSubscriber_PullOnce_ServerErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewVertGuardSubscriber(srv.URL, "k", nil, zerolog.Nop())
	if err := s.pullOnce(context.Background()); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestVertGuardSubscriber_PullOnce_CallbackErrorNotMarkedSeen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"advisories":[{"id":"adv-err","payload":{}}]}`))
	}))
	defer srv.Close()

	calls := 0
	onAdvisory := func(ctx context.Context, id string, payload map[string]any) error {
		calls++
		return context.DeadlineExceeded
	}

	s := NewVertGuardSubscriber(srv.URL, "k", onAdvisory, zerolog.Nop())
	if err := s.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce should not itself error when a callback fails: %v", err)
	}
	if err := s.pullOnce(context.Background()); err != nil {
		t.Fatalf("pullOnce (2nd): %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 (advisory not marked seen after a failed callback, so it retries)", calls)
	}
}
