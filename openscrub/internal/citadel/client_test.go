package citadel

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestSignCoversTimestampAndBody(t *testing.T) {
	got := Sign("secret", "1700000000", []byte("body"))
	mac := hmac.New(sha256.New, []byte("secret"))
	mac.Write([]byte("1700000000."))
	mac.Write([]byte("body"))
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	// Same body under a different timestamp must produce a different
	// signature — that's the whole point of the bind.
	if Sign("secret", "1700000001", []byte("body")) == got {
		t.Fatal("signature must change when timestamp changes")
	}
}

func TestClientDryRunSkipsHTTP(t *testing.T) {
	c := New(Config{DryRun: true}, zerolog.Nop())
	out, err := c.Submit(context.Background(), map[string]any{"foo": "bar"})
	if err != nil {
		t.Fatal(err)
	}
	if out != SubmitDryRun {
		t.Fatalf("expected SubmitDryRun, got %v", out)
	}
}

func TestClientSubmitSignsAndPosts(t *testing.T) {
	type capture struct {
		ts, sig, src string
		body         []byte
	}
	got := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.ts = r.Header.Get("X-Timestamp")
		got.sig = r.Header.Get("X-Signature")
		got.src = r.Header.Get("X-Source")
		got.body = body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := New(Config{BaseURL: srv.URL, HMACSecret: "key", NodeName: "n"}, zerolog.Nop())
	ev := NewEnvelope("openscrub.test", "n")
	out, err := c.Submit(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if out != SubmitDelivered {
		t.Fatalf("expected SubmitDelivered, got %v", out)
	}
	if got.src != "openscrub" {
		t.Fatalf("X-Source = %q", got.src)
	}
	if _, err := strconv.ParseInt(got.ts, 10, 64); err != nil {
		t.Fatalf("X-Timestamp not numeric: %v", err)
	}
	if got.sig != Sign("key", got.ts, got.body) {
		t.Fatalf("signature mismatch")
	}
	var decoded map[string]any
	if err := json.Unmarshal(got.body, &decoded); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if decoded["type"] != "openscrub.test" {
		t.Fatalf("type = %v", decoded["type"])
	}
}

func TestClientErrorOnNon2xx(t *testing.T) {
	// 4xx responses are non-retryable and must surface to the caller.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("nope"))
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second}, zerolog.Nop())
	if _, err := c.Submit(context.Background(), map[string]any{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClientQueuesTransient5xx(t *testing.T) {
	// 5xx is treated as transient: Submit must not error; the event
	// is buffered for the retry loop instead.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, HMACSecret: "k", HTTPTimeout: time.Second}, zerolog.Nop())
	out, err := c.Submit(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("transient should not surface: %v", err)
	}
	if out != SubmitQueued {
		t.Fatalf("expected SubmitQueued, got %v", out)
	}
	if len(c.queue) != 1 {
		t.Fatalf("expected event queued, got %d", len(c.queue))
	}
}
