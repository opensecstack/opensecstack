package opensecstack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
			atomic.AddInt32(&authCalls, 1)
			// Always return the fresh token so the retry after 401 succeeds.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, freshToken)
			return
		}
		if r.URL.Path == "/api/v1/organisations" {
			n := atomic.AddInt32(&reqCalls, 1)
			auth := r.Header.Get("Authorization")
			if n == 1 || auth != "Bearer "+freshToken {
				// First request (stale token) or still stale: return 401.
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

// makeNIS2Server creates an httptest.Server that handles auth and delegates
// everything else to handler, mirroring makeAPIGuardServer for NIS2 Compass.
func makeNIS2Server(t *testing.T, token string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"token":%q}`, token)
			return
		}
		handler(w, r)
	}))
}

// ----------------------------------------------------------------------------
// TestGetOrganisation_Success
// ----------------------------------------------------------------------------

func TestGetOrganisation_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := Organisation{ID: "org-get-1", Name: "GetOrg", Industry: "tech", Country: "DE"}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/organisations/org-get-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetOrganisation(t.Context(), "org-get-1")
	if err != nil {
		t.Fatalf("GetOrganisation: %v", err)
	}
	if got.ID != want.ID || got.Name != want.Name {
		t.Errorf("unexpected org: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestPatchOrganisation_Success
// ----------------------------------------------------------------------------

func TestPatchOrganisation_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/organisations/org-patch-1" || r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		var req PatchOrganisationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		updated := Organisation{ID: "org-patch-1", Name: req.Name, Industry: "tech", Country: "DE"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.PatchOrganisation(t.Context(), "org-patch-1", PatchOrganisationRequest{Name: "Renamed Org"})
	if err != nil {
		t.Fatalf("PatchOrganisation: %v", err)
	}
	if got.Name != "Renamed Org" {
		t.Errorf("Name: got %q, want Renamed Org", got.Name)
	}
}

// ----------------------------------------------------------------------------
// TestDeleteOrganisation_Success
// ----------------------------------------------------------------------------

func TestDeleteOrganisation_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var called bool

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/organisations/org-del-1" && r.Method == http.MethodDelete {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.DeleteOrganisation(t.Context(), "org-del-1"); err != nil {
		t.Fatalf("DeleteOrganisation: %v", err)
	}
	if !called {
		t.Error("DELETE endpoint was not called")
	}
}

// ----------------------------------------------------------------------------
// TestGetAssessments_Success
// ----------------------------------------------------------------------------

func TestGetAssessments_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := []Assessment{
		{ID: "asmt-1", OrgID: "org-1", Title: "Q1 Assessment", Status: "draft"},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/organisations/org-1/assessments" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	asmts, err := c.GetAssessments(t.Context(), "org-1", GetAssessmentsOptions{})
	if err != nil {
		t.Fatalf("GetAssessments: %v", err)
	}
	if len(asmts) != 1 || asmts[0].ID != "asmt-1" {
		t.Errorf("unexpected assessments: %+v", asmts)
	}
}

// ----------------------------------------------------------------------------
// TestCreateAssessment_Success
// ----------------------------------------------------------------------------

func TestCreateAssessment_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/organisations/org-2/assessments" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req CreateAssessmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		created := Assessment{ID: "asmt-new", OrgID: "org-2", Title: req.Title, Status: "draft"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	asmt, err := c.CreateAssessment(t.Context(), "org-2", CreateAssessmentRequest{Title: "Annual NIS2"})
	if err != nil {
		t.Fatalf("CreateAssessment: %v", err)
	}
	if asmt.ID != "asmt-new" || asmt.Title != "Annual NIS2" {
		t.Errorf("unexpected assessment: %+v", asmt)
	}
}

// ----------------------------------------------------------------------------
// TestGetAssessment_Success
// ----------------------------------------------------------------------------

func TestGetAssessment_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	avg := 6.5
	want := Assessment{
		ID: "asmt-get-1", OrgID: "org-1", Title: "Get Me", Status: "in_progress",
		Stats: &AssessmentStats{Total: 10, AvgRiskScore: &avg},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-get-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetAssessment(t.Context(), "asmt-get-1")
	if err != nil {
		t.Fatalf("GetAssessment: %v", err)
	}
	if got.ID != want.ID || got.Stats == nil || got.Stats.Total != 10 {
		t.Errorf("unexpected assessment: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestPatchAssessment_Success
// ----------------------------------------------------------------------------

func TestPatchAssessment_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-patch-1" || r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		var req PatchAssessmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		updated := Assessment{ID: "asmt-patch-1", OrgID: "org-1", Title: "Updated", Status: req.Status}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.PatchAssessment(t.Context(), "asmt-patch-1", PatchAssessmentRequest{Status: "under_review"})
	if err != nil {
		t.Fatalf("PatchAssessment: %v", err)
	}
	if got.Status != "under_review" {
		t.Errorf("Status: got %q, want under_review", got.Status)
	}
}

// ----------------------------------------------------------------------------
// TestDeleteAssessment_Success
// ----------------------------------------------------------------------------

func TestDeleteAssessment_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var called bool

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/assessments/asmt-del-1" && r.Method == http.MethodDelete {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.DeleteAssessment(t.Context(), "asmt-del-1"); err != nil {
		t.Fatalf("DeleteAssessment: %v", err)
	}
	if !called {
		t.Error("DELETE endpoint was not called")
	}
}

// ----------------------------------------------------------------------------
// TestGetControls_Success
// ----------------------------------------------------------------------------

func TestGetControls_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := []Control{
		{ID: "ctrl-a", AssessmentID: "asmt-1", MeasureRef: "a", Status: "compliant"},
		{ID: "ctrl-b", AssessmentID: "asmt-1", MeasureRef: "b", Status: "non_compliant"},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-1/controls" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	controls, err := c.GetControls(t.Context(), "asmt-1")
	if err != nil {
		t.Fatalf("GetControls: %v", err)
	}
	if len(controls) != 2 || controls[0].MeasureRef != "a" {
		t.Errorf("unexpected controls: %+v", controls)
	}
}

// ----------------------------------------------------------------------------
// TestListControls_WithFilters
// ----------------------------------------------------------------------------

func TestListControls_WithFilters(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-2/controls" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("status") != "non_compliant" {
			http.Error(w, "missing status filter", http.StatusBadRequest)
			return
		}
		if q.Get("nist_category") != "protect" {
			http.Error(w, "missing nist_category filter", http.StatusBadRequest)
			return
		}
		want := []Control{{ID: "ctrl-c", MeasureRef: "c", Status: "non_compliant"}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	controls, err := c.ListControls(t.Context(), "asmt-2", ListControlsOptions{
		Status:       "non_compliant",
		NistCategory: "protect",
	})
	if err != nil {
		t.Fatalf("ListControls: %v", err)
	}
	if len(controls) != 1 || controls[0].MeasureRef != "c" {
		t.Errorf("unexpected controls: %+v", controls)
	}
}

// ----------------------------------------------------------------------------
// TestGetControl_Success
// ----------------------------------------------------------------------------

func TestGetControl_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := Control{ID: "ctrl-e", AssessmentID: "asmt-3", MeasureRef: "e", Status: "compliant"}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-3/controls/e" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetControl(t.Context(), "asmt-3", "e")
	if err != nil {
		t.Fatalf("GetControl: %v", err)
	}
	if got.MeasureRef != "e" || got.Status != "compliant" {
		t.Errorf("unexpected control: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestPatchControl_Success
// ----------------------------------------------------------------------------

func TestPatchControl_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-4/controls/f" || r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		var req PatchControlRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		updated := Control{ID: "ctrl-f", AssessmentID: "asmt-4", MeasureRef: "f", Status: req.Status, Notes: req.Notes}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.PatchControl(t.Context(), "asmt-4", "f", PatchControlRequest{
		Status: "compliant",
		Notes:  "Reviewed and confirmed",
	})
	if err != nil {
		t.Fatalf("PatchControl: %v", err)
	}
	if got.Status != "compliant" || got.Notes != "Reviewed and confirmed" {
		t.Errorf("unexpected control: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestListArtifacts_Success
// ----------------------------------------------------------------------------

func TestListArtifacts_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := []Artifact{
		{ID: "art-1", AssessmentID: "asmt-5", Filename: "policy.pdf", Type: "policy"},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-5/artifacts" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	arts, err := c.ListArtifacts(t.Context(), "asmt-5")
	if err != nil {
		t.Fatalf("ListArtifacts: %v", err)
	}
	if len(arts) != 1 || arts[0].ID != "art-1" {
		t.Errorf("unexpected artifacts: %+v", arts)
	}
}

// ----------------------------------------------------------------------------
// TestUploadArtifact_Success
// ----------------------------------------------------------------------------

func TestUploadArtifact_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	dir := t.TempDir()
	filePath := filepath.Join(dir, "evidence.txt")
	if err := os.WriteFile(filePath, []byte("evidence content"), 0600); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-6/artifacts" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		ct := r.Header.Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "multipart/form-data" {
			http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "parse multipart: "+err.Error(), http.StatusBadRequest)
			return
		}
		if r.FormValue("type") != "evidence" {
			http.Error(w, "missing type field", http.StatusBadRequest)
			return
		}
		art := Artifact{ID: "art-new", AssessmentID: "asmt-6", Type: "evidence", Filename: "evidence.txt"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(art)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.UploadArtifact(t.Context(), "asmt-6", filePath, "evidence", "", "test evidence")
	if err != nil {
		t.Fatalf("UploadArtifact: %v", err)
	}
	if got.ID != "art-new" || got.Type != "evidence" {
		t.Errorf("unexpected artifact: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestGetArtifact_Success
// ----------------------------------------------------------------------------

func TestGetArtifact_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := Artifact{ID: "art-get-1", AssessmentID: "asmt-7", Filename: "report.pdf", Type: "report"}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/artifacts/art-get-1" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetArtifact(t.Context(), "art-get-1")
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if got.ID != want.ID || got.Filename != want.Filename {
		t.Errorf("unexpected artifact: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestDownloadArtifact_Success
// ----------------------------------------------------------------------------

func TestDownloadArtifact_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	content := []byte("PDF binary content here")

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/artifacts/art-dl-1/download" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(content)
	})
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "downloaded.bin")
	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.DownloadArtifact(t.Context(), "art-dl-1", dest); err != nil {
		t.Fatalf("DownloadArtifact: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("reading downloaded file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content mismatch: got %q", string(got))
	}
}

// ----------------------------------------------------------------------------
// TestDeleteArtifact_Success
// ----------------------------------------------------------------------------

func TestDeleteArtifact_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var called bool

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/artifacts/art-del-1" && r.Method == http.MethodDelete {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.DeleteArtifact(t.Context(), "art-del-1"); err != nil {
		t.Fatalf("DeleteArtifact: %v", err)
	}
	if !called {
		t.Error("DELETE endpoint was not called")
	}
}

// ----------------------------------------------------------------------------
// TestListAPIKeys_Success
// ----------------------------------------------------------------------------

func TestListAPIKeys_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := []APIKey{
		{ID: "key-1", Scope: "read", IsActive: true},
		{ID: "key-2", Scope: "admin", IsActive: false},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/api-keys" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	keys, err := c.ListAPIKeys(t.Context())
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(keys) != 2 || keys[0].ID != "key-1" {
		t.Errorf("unexpected keys: %+v", keys)
	}
}

// ----------------------------------------------------------------------------
// TestCreateAPIKey_Success
// ----------------------------------------------------------------------------

func TestCreateAPIKey_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/api-keys" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		created := APIKey{ID: "key-new", Scope: "read", IsActive: true, Key: "plaintext-key-value"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.CreateAPIKey(t.Context(), CreateAPIKeyRequest{Label: "ci-key", Scope: "read"})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if got.ID != "key-new" || got.Key == "" {
		t.Errorf("unexpected key: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestRevokeAPIKey_Success
// ----------------------------------------------------------------------------

func TestRevokeAPIKey_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var called bool

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/api-keys/key-rev-1" && r.Method == http.MethodDelete {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	if err := c.RevokeAPIKey(t.Context(), "key-rev-1"); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if !called {
		t.Error("DELETE endpoint was not called")
	}
}

// ----------------------------------------------------------------------------
// TestGenerateReport_Success
// ----------------------------------------------------------------------------

func TestGenerateReport_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	pdfData := []byte("%PDF-1.4 fake pdf content")

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-rpt-1/report" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Write(pdfData)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GenerateReport(t.Context(), "asmt-rpt-1")
	if err != nil {
		t.Fatalf("GenerateReport: %v", err)
	}
	if string(got) != string(pdfData) {
		t.Errorf("PDF data mismatch: got %q", string(got))
	}
}

// ----------------------------------------------------------------------------
// TestGetReportStream_NIS2_Success
// ----------------------------------------------------------------------------

func TestGetReportStream_NIS2_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	sarifData := `{"version":"2.1.0","runs":[]}`

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/assessments/asmt-stream-1/report" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("format") != "sarif" {
			http.Error(w, "unexpected format", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, sarifData)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	var buf strings.Builder
	if err := c.GetReportStream(t.Context(), "asmt-stream-1", "sarif", &buf); err != nil {
		t.Fatalf("GetReportStream: %v", err)
	}
	if buf.String() != sarifData {
		t.Errorf("data mismatch: got %q", buf.String())
	}
}

// ----------------------------------------------------------------------------
// TestGetAuditLog_NIS2_Success
// ----------------------------------------------------------------------------

func TestGetAuditLog_NIS2_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := []NIS2AuditEntry{
		{ID: "nis2-audit-1", Action: "organisation.created", Actor: "api_key:key-1"},
		{ID: "nis2-audit-2", Action: "assessment.status_changed", Actor: "api_key:key-1"},
	}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") == "" || r.URL.Query().Get("page") == "" {
			http.Error(w, "missing pagination", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	entries, err := c.GetAuditLog(t.Context(), 20, 1)
	if err != nil {
		t.Fatalf("GetAuditLog: %v", err)
	}
	if len(entries) != 2 || entries[0].ID != "nis2-audit-1" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

// ----------------------------------------------------------------------------
// TestGetAuditEntry_NIS2_Success
// ----------------------------------------------------------------------------

func TestGetAuditEntry_NIS2_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := NIS2AuditEntry{ID: "nis2-audit-42", Action: "control.patched", Actor: "api_key:key-2"}

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit/nis2-audit-42" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetAuditEntry(t.Context(), "nis2-audit-42")
	if err != nil {
		t.Fatalf("GetAuditEntry: %v", err)
	}
	if got.ID != want.ID || got.Action != want.Action {
		t.Errorf("unexpected entry: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestNIS2CompassClient_ContextCancellation
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// TestGetHealth_Success
// ----------------------------------------------------------------------------

func TestGetHealth_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		// Health endpoint must NOT require an Authorization header.
		if r.Header.Get("Authorization") != "" {
			t.Error("GetHealth sent an Authorization header; endpoint should be unauthenticated")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetHealth(t.Context())
	if err != nil {
		t.Fatalf("GetHealth: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("expected status ok, got %q", got.Status)
	}
}

// ----------------------------------------------------------------------------
// TestGetHealthDetail_Success
// ----------------------------------------------------------------------------

func TestGetHealthDetail_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeNIS2Server(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health/detail" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok","version":"1.0.0","db":"ok","redis":"ok"}`)
	})
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	got, err := c.GetHealthDetail(t.Context())
	if err != nil {
		t.Fatalf("GetHealthDetail: %v", err)
	}
	if got.Status != "ok" || got.DB != "ok" || got.Redis != "ok" {
		t.Errorf("unexpected health detail: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestGetHealth_ServiceUnavailable
// ----------------------------------------------------------------------------

func TestGetHealth_ServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"status":"degraded"}`)
	}))
	defer srv.Close()

	c := NewNIS2CompassClient(srv.URL, "test-key")
	_, err := c.GetHealth(t.Context())
	if err == nil {
		t.Error("expected error on 503, got nil")
	}
}

// ----------------------------------------------------------------------------
// TestNIS2CompassClient_ContextCancellation
// ----------------------------------------------------------------------------

// TestNIS2CompassClient_ContextCancellation verifies that a context cancelled
// before the server responds causes GetOrganisations to return a non-nil error.
func TestNIS2CompassClient_ContextCancellation(t *testing.T) {
	// Slow server: delays 2 seconds before replying so the short-lived context
	// is guaranteed to expire first.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	client := NewNIS2CompassClient(slow.URL, "token")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.GetOrganisations(ctx, GetOrganisationsOptions{})
	if err == nil {
		t.Error("expected error on context cancellation, got nil")
	}
}
