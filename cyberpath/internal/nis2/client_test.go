package nis2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	return New(Options{
		BaseURL:     baseURL,
		HTTPTimeout: 1 * time.Second,
		Logger:      zerolog.Nop(),
	})
}

func TestHealth_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path = %q, want /healthz", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	ok, err := c.Health(context.Background())
	if err != nil || !ok {
		t.Fatalf("health: ok=%v err=%v", ok, err)
	}
}

func TestHealth_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL)
	ok, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for 404 response")
	}
}

func TestHealth_NoBaseURL(t *testing.T) {
	c := newTestClient(t, "")
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("expected error when base URL is not configured")
	}
}

func TestHealth_TransportError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // connection refused

	c := New(Options{BaseURL: url, HTTPTimeout: 200 * time.Millisecond, Logger: zerolog.Nop()})
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("expected transport error")
	}
}
