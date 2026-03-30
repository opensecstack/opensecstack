package citadel

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// logRequest captures a single HTTP request received by the test server.
type logRequest struct {
	method  string
	path    string
	authHdr string
	body    map[string]interface{}
}

// newCaptureServer creates an httptest.Server whose handler sends received
// requests to the returned channel (buffered). Call ts.Close() when done.
func newCaptureServer(t *testing.T, statusCode int, ch chan<- logRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]interface{}
		_ = json.Unmarshal(raw, &body)
		ch <- logRequest{
			method:  r.Method,
			path:    r.URL.Path,
			authHdr: r.Header.Get("Authorization"),
			body:    body,
		}
		w.WriteHeader(statusCode)
	}))
}

// drain calls c.Drain with a generous timeout so tests don't hang forever.
func drain(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Drain(ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestClient_NoOp_WhenBaseURLEmpty(t *testing.T) {
	// A server that would record hits; we expect it to receive none.
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	c := New("", "some-key")
	c.LogEvent("ACCESS", "u1", "admin", "success", "module", "res-1", nil)

	// Give a short window for any stray request to arrive.
	drain(t, c)
	select {
	case req := <-ch:
		t.Errorf("expected no HTTP request, but received one: %+v", req)
	default:
		// correct — nothing was sent
	}
}

func TestClient_SuccessfulEventDelivery(t *testing.T) {
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	c := New(ts.URL, "")
	c.LogEvent("ACCESS", "user-42", "viewer", "success", "apiguard", "endpoint-1",
		map[string]interface{}{"extra": "data"})
	drain(t, c)

	select {
	case req := <-ch:
		if req.method != http.MethodPost {
			t.Errorf("expected POST, got %s", req.method)
		}
		if req.path != "/v1/log" {
			t.Errorf("expected path /v1/log, got %s", req.path)
		}
		// Verify key JSON fields.
		if req.body["action_type"] != "ACCESS" {
			t.Errorf("action_type = %v, want ACCESS", req.body["action_type"])
		}
		if req.body["actor_role"] != "viewer" {
			t.Errorf("actor_role = %v, want viewer", req.body["actor_role"])
		}
		if req.body["result_status"] != "success" {
			t.Errorf("result_status = %v, want success", req.body["result_status"])
		}
		if req.body["system_module"] != "apiguard" {
			t.Errorf("system_module = %v, want apiguard", req.body["system_module"])
		}
		if req.body["resource_id"] != "endpoint-1" {
			t.Errorf("resource_id = %v, want endpoint-1", req.body["resource_id"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestClient_AuthorizationHeader_WhenAPIKeySet(t *testing.T) {
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	apiKey := "secret-token-xyz"
	c := New(ts.URL, apiKey)
	c.LogEvent("ACCESS", "", "", "success", "mod", "res", nil)
	drain(t, c)

	select {
	case req := <-ch:
		want := "Bearer " + apiKey
		if req.authHdr != want {
			t.Errorf("Authorization header = %q, want %q", req.authHdr, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestClient_NoAuthorizationHeader_WhenAPIKeyEmpty(t *testing.T) {
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	c := New(ts.URL, "") // empty API key
	c.LogEvent("ACCESS", "", "", "success", "mod", "res", nil)
	drain(t, c)

	select {
	case req := <-ch:
		if req.authHdr != "" {
			t.Errorf("expected no Authorization header, got %q", req.authHdr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}

func TestClient_ServerError500_SilentlyDiscarded(t *testing.T) {
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusInternalServerError, ch)
	defer ts.Close()

	c := New(ts.URL, "")
	// LogEvent must not block or return an error (it is fire-and-forget).
	c.LogEvent("ACCESS", "", "", "error", "mod", "res", nil)

	// Drain must complete without panic even though the server returned 500.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Drain(ctx)

	// Server should have received the request despite the 500.
	select {
	case <-ch:
		// good
	default:
		t.Error("expected server to receive the request even on 500 response")
	}
}

func TestClient_Drain_RespectsContextCancellation(t *testing.T) {
	// Use a server with an artificial delay so the goroutine is still in-flight
	// when we cancel the context.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block until the test's context is done (it will be cancelled quickly).
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	c := New(slow.URL, "")
	c.LogEvent("ACCESS", "", "", "success", "mod", "res", nil)

	// Cancel almost immediately — Drain must return before the slow handler finishes.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	c.Drain(ctx)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Errorf("Drain did not respect context cancellation; took %v", elapsed)
	}
}

func TestClient_NilClient_IsSafe(t *testing.T) {
	var c *Client

	// Neither call should panic.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panic on nil client: %v", r)
		}
	}()

	c.LogEvent("ACCESS", "", "", "success", "mod", "res", nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c.Drain(ctx)
}

func TestClient_MultipleConcurrentLogEvents(t *testing.T) {
	const n = 10
	ch := make(chan logRequest, n)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	c := New(ts.URL, "")

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.LogEvent("ACCESS", "", "", "success", "mod", "res", nil)
		}()
	}
	wg.Wait()

	drain(t, c)

	// Count received requests.
	received := 0
loop:
	for {
		select {
		case <-ch:
			received++
		default:
			break loop
		}
	}

	if received != n {
		t.Errorf("expected %d requests, received %d", n, received)
	}
}

// TestClient_MetadataActorSubject verifies that a non-empty actorUserID is
// forwarded as actor_subject inside the metadata envelope.
func TestClient_MetadataActorSubject(t *testing.T) {
	ch := make(chan logRequest, 1)
	ts := newCaptureServer(t, http.StatusOK, ch)
	defer ts.Close()

	c := New(ts.URL, "")
	c.LogEvent("ACCESS", "jwt-sub-abc", "admin", "success", "mod", "res", nil)
	drain(t, c)

	select {
	case req := <-ch:
		meta, ok := req.body["metadata"].(map[string]interface{})
		if !ok {
			t.Fatalf("metadata field missing or wrong type: %v", req.body["metadata"])
		}
		if sub, _ := meta["actor_subject"].(string); !strings.Contains(sub, "jwt-sub-abc") {
			t.Errorf("actor_subject in metadata = %q, want to contain jwt-sub-abc", sub)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for request")
	}
}
