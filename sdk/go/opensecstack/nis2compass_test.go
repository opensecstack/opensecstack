package opensecstack

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// makeTestJWT builds a minimal signed-looking JWT whose payload contains the
// given exp Unix timestamp. The signature segment is a dummy value; the SDK
// only decodes the payload so a real signature is not needed for tests.
func makeTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]interface{}{
		"sub": "test",
		"exp": exp,
	})
	payloadEnc := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + payloadEnc + ".signature"
}

// authHandler returns an HTTP handler that serves a JWT auth response and
// increments the provided counter each time it is called.
func authHandler(t *testing.T, token string, counter *int32) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/token" || r.Method != http.MethodPost {
			return
		}
		atomic.AddInt32(counter, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":%q}`, token)
	}
}

// ----------------------------------------------------------------------------
// TestAuthenticate_Success
// ----------------------------------------------------------------------------

func TestAuthenticate_Success(t *testing.T) {
	var authCalls int32
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHandler(t, token, &authCalls)(w, r)
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 auth call, got %d", got)
	}
	c.mu.RLock()
	if c.jwt != token {
		t.Errorf("expected cached token %q, got %q", token, c.jwt)
	}
	c.mu.RUnlock()
}

// ----------------------------------------------------------------------------
// TestAuthenticate_Cached
// ----------------------------------------------------------------------------

func TestAuthenticate_Cached(t *testing.T) {
	var authCalls int32
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHandler(t, token, &authCalls)(w, r)
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")

	// First call — should hit the server.
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("first authenticate failed: %v", err)
	}
	// Second call — token is cached and not near expiry; must NOT hit server.
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("second authenticate failed: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 auth call, got %d (token was not cached)", got)
	}
}

// ----------------------------------------------------------------------------
// TestDo_401Retry
// ----------------------------------------------------------------------------

func TestDo_401Retry(t *testing.T) {
	var authCalls int32
	var reqCalls int32

	// First token (stale) — expires in far future so authenticate() fast-path
	// thinks it's valid; the server will reject it with 401 to force a refresh.
	staleToken := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	freshToken := makeTestJWT(time.Now().Add(2 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			n := atomic.AddInt32(&authCalls, 1)
			tok := staleToken
			if n > 1 {
				tok = freshToken
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, tok)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			n := atomic.AddInt32(&reqCalls, 1)
			auth := r.Header.Get("Authorization")
			if n == 1 || auth != "Bearer "+freshToken {
				// First request or still stale token: return 401.
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")

	// Pre-seed the stale token so the fast path believes we are authenticated.
	c.mu.Lock()
	c.jwt = staleToken
	c.tokenExpiry = time.Now().Add(1 * time.Hour)
	c.mu.Unlock()

	_, err := c.GetOrganisations(t.Context(), GetOrganisationsOptions{})
	if err != nil {
		t.Fatalf("GetOrganisations failed: %v", err)
	}
	// authenticate should have been called once (to refresh the stale token).
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 re-auth call on 401, got %d", got)
	}
}

// ----------------------------------------------------------------------------
// TestDo_RateLimitRetry
// ----------------------------------------------------------------------------

func TestDo_RateLimitRetry(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var reqCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			n := atomic.AddInt32(&reqCalls, 1)
			if n == 1 {
				// First attempt: 429 with short Retry-After.
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			// Second attempt: success.
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	start := time.Now()
	_, err := c.GetOrganisations(t.Context(), GetOrganisationsOptions{})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success after retry, got error: %v", err)
	}
	if got := atomic.LoadInt32(&reqCalls); got != 2 {
		t.Errorf("expected 2 request attempts (1 429 + 1 retry), got %d", got)
	}
	if elapsed < 900*time.Millisecond {
		t.Errorf("expected at least ~1s sleep for Retry-After:1, elapsed=%v", elapsed)
	}
}

// ----------------------------------------------------------------------------
// TestDo_RateLimitImmediate
// ----------------------------------------------------------------------------

func TestDo_RateLimitImmediate(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var reqCalls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			atomic.AddInt32(&reqCalls, 1)
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	start := time.Now()
	_, err := c.GetOrganisations(t.Context(), GetOrganisationsOptions{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected RateLimitError, got nil")
	}
	var rle *RateLimitError
	if !isRateLimitError(err, &rle) {
		t.Errorf("expected *RateLimitError, got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(&reqCalls); got != 1 {
		t.Errorf("expected exactly 1 request (no retry for Retry-After>60), got %d", got)
	}
	// Must not have slept 120 seconds.
	if elapsed > 5*time.Second {
		t.Errorf("should return immediately for Retry-After>60, elapsed=%v", elapsed)
	}
}

// isRateLimitError unwraps err looking for a *RateLimitError.
func isRateLimitError(err error, out **RateLimitError) bool {
	if err == nil {
		return false
	}
	// Walk the error chain manually (errors.As would work too but avoid import).
	type unwrapper interface{ Unwrap() error }
	for {
		if rle, ok := err.(*RateLimitError); ok {
			if out != nil {
				*out = rle
			}
			return true
		}
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
}

// ----------------------------------------------------------------------------
// TestDo_NoRedirectFollow
// ----------------------------------------------------------------------------

func TestDo_NoRedirectFollow(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			http.Redirect(w, r, "/api/v1/other", http.StatusFound)
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	// The client must NOT follow the redirect; GetOrganisations should return
	// an error (or a non-2xx response) rather than following to /api/v1/other.
	_, err := c.GetOrganisations(t.Context(), GetOrganisationsOptions{})
	if err == nil {
		t.Fatal("expected an error when server issues 302, but got nil")
	}
}

// ----------------------------------------------------------------------------
// TestProactiveTokenExpiry
// ----------------------------------------------------------------------------

func TestProactiveTokenExpiry(t *testing.T) {
	var authCalls int32

	// Tokens: first one expires within the 60-second window (should be treated
	// as expired); second one is valid for 2 hours.
	nearlyExpiredToken := makeTestJWT(time.Now().Add(30 * time.Second).Unix())
	freshToken := makeTestJWT(time.Now().Add(2 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			n := atomic.AddInt32(&authCalls, 1)
			tok := freshToken
			if n == 1 {
				tok = nearlyExpiredToken
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, tok)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")

	// First authenticate — stores nearlyExpiredToken with expiry < now+60s.
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("first authenticate: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 auth call, got %d", got)
	}

	// Second call to authenticate: token expiry is within 60s window, so the
	// client should re-authenticate.
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("second authenticate: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 2 {
		t.Errorf("expected 2 auth calls after proactive expiry, got %d", got)
	}
}

// ----------------------------------------------------------------------------
// TestGetOrganisations_Success
// ----------------------------------------------------------------------------

func TestGetOrganisations_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	want := []Organisation{
		{ID: "org-1", Name: "Acme Corp", Industry: "technology", Country: "DE"},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(want)
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	orgs, err := c.GetOrganisations(t.Context(), GetOrganisationsOptions{})
	if err != nil {
		t.Fatalf("GetOrganisations: %v", err)
	}
	if len(orgs) != 1 || orgs[0].ID != "org-1" {
		t.Errorf("unexpected response: %+v", orgs)
	}
}

// ----------------------------------------------------------------------------
// TestCreateOrganisation_Success
// ----------------------------------------------------------------------------

func TestCreateOrganisation_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		if r.URL.Path == "/api/v1/organisations" && r.Method == http.MethodPost {
			var req CreateOrganisationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			created := Organisation{
				ID:       "new-org-id",
				Name:     req.Name,
				Industry: req.Industry,
				Country:  req.Country,
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(created)
		}
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	org, err := c.CreateOrganisation(t.Context(), CreateOrganisationRequest{
		Name:     "New Org",
		Industry: "finance",
		Country:  "FR",
	})
	if err != nil {
		t.Fatalf("CreateOrganisation: %v", err)
	}
	if org.ID != "new-org-id" {
		t.Errorf("expected ID 'new-org-id', got %q", org.ID)
	}
	if org.Name != "New Org" {
		t.Errorf("expected Name 'New Org', got %q", org.Name)
	}
}
