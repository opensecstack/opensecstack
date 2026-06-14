package nis2

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func newTestClient(t *testing.T, baseURL, secret string) *Client {
	t.Helper()
	return New(Options{
		BaseURL:     baseURL,
		HMACSecret:  secret,
		HTTPTimeout: 1 * time.Second,
		MaxRetries:  3,
		Logger:      zerolog.Nop(),
	})
}

func TestRecommendTracks_HappyPath(t *testing.T) {
	const secret = "topsecret"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/recommend" {
			t.Errorf("path = %q", r.URL.Path)
		}
		// HMAC verification on inbound.
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-CyberPath-Timestamp")
		sig := strings.TrimPrefix(r.Header.Get("X-CyberPath-Signature"), "sha256=")
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(ts))
		h.Write([]byte("."))
		h.Write(body)
		want := hex.EncodeToString(h.Sum(nil))
		if !hmac.Equal([]byte(sig), []byte(want)) {
			t.Errorf("signature mismatch: got %s want %s", sig, want)
		}
		var req recommendRequest
		_ = json.Unmarshal(body, &req)
		if req.Gap != "art21.g" {
			t.Errorf("gap = %q", req.Gap)
		}
		_ = json.NewEncoder(w).Encode(recommendResponse{
			Gap:     req.Gap,
			Measure: "art21.g",
			Recommendations: []TrackRecommendation{
				{TrackID: "phishing-recognition", Priority: "primary", EstimatedMinutes: 120},
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, secret)
	got, err := c.RecommendTracks(context.Background(), "tenant-x", "art21.g")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 1 || got[0].TrackID != "phishing-recognition" {
		t.Fatalf("unexpected recs: %+v", got)
	}
}

func TestRecommendTracks_RetriesOn5xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n < 3 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(recommendResponse{Recommendations: []TrackRecommendation{}})
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, "s")
	if _, err := c.RecommendTracks(context.Background(), "", "art21.g"); err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRecommendTracks_NoRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad gap", http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, "s")
	_, err := c.RecommendTracks(context.Background(), "", "garbage")
	if err == nil {
		t.Fatal("expected error")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("calls = %d, want 1 (no retry on 4xx)", calls)
	}
}

func TestRecommendTracks_TransportError(t *testing.T) {
	// Closed server → connection refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := New(Options{
		BaseURL:     url,
		HMACSecret:  "s",
		HTTPTimeout: 200 * time.Millisecond,
		MaxRetries:  1,
		Logger:      zerolog.Nop(),
	})
	if _, err := c.RecommendTracks(context.Background(), "", "art21.g"); err == nil {
		t.Fatal("expected transport error")
	}
}

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := newTestClient(t, srv.URL, "s")
	ok, err := c.Health(context.Background())
	if err != nil || !ok {
		t.Fatalf("health: ok=%v err=%v", ok, err)
	}
}
