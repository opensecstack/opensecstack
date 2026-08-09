package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

func TestNewRegistry_RegistersAllTenModules(t *testing.T) {
	r := NewRegistry()
	all := r.All()
	if len(all) != 10 {
		t.Fatalf("expected 10 registered modules, got %d", len(all))
	}
	wantIDs := []string{
		"a1_bola", "a2_auth", "a3_mass_assignment", "a4_rate_limit",
		"a5_function_auth", "a6_business_flow", "a7_ssrf",
		"a8_misconfiguration", "a9_inventory", "a10_unsafe_consumption",
	}
	for _, id := range wantIDs {
		if _, ok := r.Get(id); !ok {
			t.Errorf("expected module %q to be registered", id)
		}
	}
}

func TestRegistry_Get_UnknownIDReturnsFalse(t *testing.T) {
	r := NewRegistry()
	m, ok := r.Get("not_a_real_module")
	if ok {
		t.Error("expected ok=false for unknown module ID")
	}
	if m != nil {
		t.Error("expected nil module for unknown ID")
	}
}

func TestRegistry_Register_OverwritesSameID(t *testing.T) {
	r := &Registry{modules: make(map[string]Module)}
	first := &BOLAModule{}
	second := &BOLAModule{}
	r.Register(first)
	r.Register(second)
	if len(r.All()) != 1 {
		t.Fatalf("expected registering the same ID twice to result in 1 entry, got %d", len(r.All()))
	}
	got, _ := r.Get(first.ID())
	if got != second {
		t.Error("expected the second registration to win")
	}
}

// ---------------------------------------------------------------------------
// DefaultExecutor.Do — real HTTP round trip against httptest server
// ---------------------------------------------------------------------------

func TestDefaultExecutor_Do_SuccessfulRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test-Header", "yes")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	exec := NewDefaultExecutor(nil, 5*time.Second)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	got, err := exec.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StatusCode != http.StatusCreated {
		t.Errorf("expected status 201, got %d", got.StatusCode)
	}
	if string(got.Body) != `{"ok":true}` {
		t.Errorf("expected body to match, got %q", got.Body)
	}
	if got.Headers.Get("X-Test-Header") != "yes" {
		t.Errorf("expected X-Test-Header=yes, got %q", got.Headers.Get("X-Test-Header"))
	}
	if got.Duration <= 0 {
		t.Error("expected non-zero duration")
	}
}

func TestDefaultExecutor_Do_DoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("should not be reached"))
	}))
	defer srv.Close()

	exec := NewDefaultExecutor(nil, 5*time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/start", nil)
	got, err := exec.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Security tests must see the raw redirect response, not a followed one —
	// a followed redirect could mask a finding on the original endpoint.
	if got.StatusCode != http.StatusFound {
		t.Errorf("expected 302 (redirect not followed), got %d", got.StatusCode)
	}
	if got.Headers.Get("Location") != "/target" {
		t.Errorf("expected Location header to be preserved, got %q", got.Headers.Get("Location"))
	}
}

func TestDefaultExecutor_Do_ConnectionErrorReturnsWrappedError(t *testing.T) {
	exec := NewDefaultExecutor(nil, 1*time.Second)
	// Nothing is listening on this port.
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/unreachable", nil)
	_, err := exec.Do(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for unreachable target")
	}
	if !strings.Contains(err.Error(), "http request failed") {
		t.Errorf("expected wrapped error message, got %q", err.Error())
	}
}

func TestDefaultExecutor_Do_TruncatesBodyAtMaxSize(t *testing.T) {
	const oneMiB = 1 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 8192)
		for i := range chunk {
			chunk[i] = 'a'
		}
		// Write well over 1 MiB so the executor's cap must kick in.
		for written := 0; written < oneMiB+8192*4; written += len(chunk) {
			w.Write(chunk)
		}
	}))
	defer srv.Close()

	exec := NewDefaultExecutor(nil, 10*time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	got, err := exec.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got.Body) != oneMiB {
		t.Errorf("expected body truncated to exactly %d bytes, got %d", oneMiB, len(got.Body))
	}
}

func TestNewInsecureExecutor_SkipsTLSVerification(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure ok"))
	}))
	defer srv.Close()

	// A self-signed test TLS server must fail with the default (verifying) executor...
	secureExec := NewDefaultExecutor(nil, 5*time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if _, err := secureExec.Do(context.Background(), req); err == nil {
		t.Fatal("expected TLS verification error with NewDefaultExecutor against self-signed cert")
	}

	// ...but must succeed with the insecure executor (explicit opt-in).
	insecureExec := NewInsecureExecutor(5 * time.Second)
	req2, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	got, err := insecureExec.Do(context.Background(), req2)
	if err != nil {
		t.Fatalf("expected insecure executor to skip TLS verification, got error: %v", err)
	}
	if string(got.Body) != "secure ok" {
		t.Errorf("expected body 'secure ok', got %q", got.Body)
	}
}

func TestNewDefaultExecutor_NilTransportUsesDefault(t *testing.T) {
	exec := NewDefaultExecutor(nil, 5*time.Second)
	if exec.client.Transport != http.DefaultTransport {
		t.Error("expected nil transport to fall back to http.DefaultTransport")
	}
}
