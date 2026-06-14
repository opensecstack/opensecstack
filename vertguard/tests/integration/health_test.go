package integration

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/opensecstack/vertguard/internal/api/handlers"
)

func TestHealth_Unauthenticated(t *testing.T) {
	env := setupServer(t, false)
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodGet, "/api/v1/health", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status = %v, want ok", body["status"])
	}
}

func TestHealth_DegradedOnPingerFailure(t *testing.T) {
	// This variant builds its own env with a failing pinger.
	// We don't expose it via setupServer to keep that helper simple.
	t.Skip("covered by unit test; requires custom server setup not yet exposed")
}

// /livez must always be 200 regardless of DB state — kubelet uses it
// to decide kill-the-pod.
func TestLivez_AlwaysOK(t *testing.T) {
	env := setupServerWithPinger(t, false, stubPinger{err: errors.New("db down")})
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodGet, "/livez", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("livez status = %d, want 200", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "alive" {
		t.Fatalf("status = %v, want alive", body["status"])
	}
}

func TestReadyz_OKWhenPingerHealthy(t *testing.T) {
	// Reset between tests — the Ready flag is process-wide.
	handlers.Ready.Store(true)
	env := setupServerWithPinger(t, false, stubPinger{})
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodGet, "/readyz", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz status = %d, want 200", resp.StatusCode)
	}
}

func TestReadyz_503WhenPingerFails(t *testing.T) {
	handlers.Ready.Store(true)
	env := setupServerWithPinger(t, false, stubPinger{err: errors.New("db down")})
	defer env.cleanup()

	resp := doRequest(t, env, http.MethodGet, "/readyz", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d, want 503", resp.StatusCode)
	}
}

func TestReadyz_503WhenDraining(t *testing.T) {
	handlers.Ready.Store(true)
	env := setupServerWithPinger(t, false, stubPinger{})
	defer env.cleanup()

	handlers.Ready.Store(false)
	defer handlers.Ready.Store(true)

	resp := doRequest(t, env, http.MethodGet, "/readyz", "", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readyz draining status = %d, want 503", resp.StatusCode)
	}
}
