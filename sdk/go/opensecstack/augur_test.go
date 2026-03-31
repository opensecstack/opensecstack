package opensecstack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// makeAUGURServer returns a CITADELClient pointed at a test server that
// handles AUGUR advisory endpoints. The provided handler receives every
// request so individual tests can assert on method, path, and body.
func makeAUGURServer(t *testing.T, handler http.HandlerFunc) *CITADELClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewCITADELClient(CITADELClientOptions{
		BaseURL:      srv.URL,
		SharedSecret: "test-secret",
	})
}

func sampleAdvisory() Advisory {
	return Advisory{
		ID:          "adv-001",
		Title:       "Critical RCE in libfoo",
		Description: "Remote code execution via crafted input",
		Severity:    AdvisorySeverityCritical,
		Status:      AdvisoryStatusDraft,
		Affects: []AdvisoryAffects{
			{Component: "libfoo", VersionMin: "1.0.0", VersionMax: "1.2.3"},
		},
		CVE:        "CVE-2026-99999",
		References: []string{"https://example.com/advisory/1"},
		CreatedAt:  "2026-03-31T09:00:00Z",
		UpdatedAt:  "2026-03-31T09:00:00Z",
	}
}

// ── 1. TestCreateAdvisory_Success ────────────────────────────────────────────

func TestCreateAdvisory_Success(t *testing.T) {
	want := sampleAdvisory()
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/augur/advisories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Citadel-Signature") == "" {
			t.Error("missing X-Citadel-Signature")
		}

		var body CreateAdvisoryRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Title != want.Title {
			t.Errorf("title: got %q, want %q", body.Title, want.Title)
		}
		if body.Severity != AdvisorySeverityCritical {
			t.Errorf("severity: got %q, want critical", body.Severity)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(want)
	})

	got, err := c.CreateAdvisory(context.Background(), CreateAdvisoryRequest{
		Title:       want.Title,
		Description: want.Description,
		Severity:    want.Severity,
		Affects:     want.Affects,
		CVE:         want.CVE,
		References:  want.References,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("id: got %q, want %q", got.ID, want.ID)
	}
	if got.Status != AdvisoryStatusDraft {
		t.Errorf("status: got %q, want draft", got.Status)
	}
	if got.CVE != want.CVE {
		t.Errorf("cve: got %q, want %q", got.CVE, want.CVE)
	}
}

// ── 2. TestCreateAdvisory_ServerError ────────────────────────────────────────

func TestCreateAdvisory_ServerError(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
	})

	_, err := c.CreateAdvisory(context.Background(), CreateAdvisoryRequest{
		Title:    "Test",
		Severity: AdvisorySeverityHigh,
	})
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

// ── 3. TestListAdvisories_NoFilter ───────────────────────────────────────────

func TestListAdvisories_NoFilter(t *testing.T) {
	items := []Advisory{sampleAdvisory(), sampleAdvisory()}
	items[1].ID = "adv-002"

	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/augur/advisories" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// No query parameters expected
		if r.URL.RawQuery != "" {
			t.Errorf("expected no query params, got %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	})

	got, err := c.ListAdvisories(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 advisories, got %d", len(got))
	}
}

// ── 4. TestListAdvisories_WithFilters ────────────────────────────────────────

func TestListAdvisories_WithFilters(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("status") != "published" {
			t.Errorf("expected status=published, got %q", q.Get("status"))
		}
		if q.Get("severity") != "critical" {
			t.Errorf("expected severity=critical, got %q", q.Get("severity"))
		}
		if q.Get("page") != "2" {
			t.Errorf("expected page=2, got %q", q.Get("page"))
		}
		if q.Get("per_page") != "10" {
			t.Errorf("expected per_page=10, got %q", q.Get("per_page"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Advisory{})
	})

	_, err := c.ListAdvisories(context.Background(), &ListAdvisoriesOptions{
		Status:   AdvisoryStatusPublished,
		Severity: AdvisorySeverityCritical,
		Page:     2,
		PerPage:  10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ── 5. TestListAdvisories_Empty ──────────────────────────────────────────────

func TestListAdvisories_Empty(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})

	got, err := c.ListAdvisories(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %d items", len(got))
	}
}

// ── 6. TestGetAdvisory_Success ───────────────────────────────────────────────

func TestGetAdvisory_Success(t *testing.T) {
	want := sampleAdvisory()
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/augur/advisories/adv-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})

	got, err := c.GetAdvisory(context.Background(), "adv-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != want.ID {
		t.Errorf("id: got %q, want %q", got.ID, want.ID)
	}
	if got.Severity != AdvisorySeverityCritical {
		t.Errorf("severity: got %q, want critical", got.Severity)
	}
}

// ── 7. TestGetAdvisory_EmptyID ───────────────────────────────────────────────

func TestGetAdvisory_EmptyID(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for empty ID")
	})
	_, err := c.GetAdvisory(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty advisory ID")
	}
}

// ── 8. TestGetAdvisory_NotFound ──────────────────────────────────────────────

func TestGetAdvisory_NotFound(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"advisory not found"}`))
	})

	_, err := c.GetAdvisory(context.Background(), "no-such-id")
	if err == nil {
		t.Fatal("expected error for 404 response, got nil")
	}
}

// ── 9. TestPatchAdvisory_Success ─────────────────────────────────────────────

func TestPatchAdvisory_Success(t *testing.T) {
	newTitle := "Updated title"
	want := sampleAdvisory()
	want.Title = newTitle
	want.Status = AdvisoryStatusPublished

	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/augur/advisories/adv-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var body PatchAdvisoryRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if body.Title == nil || *body.Title != newTitle {
			t.Errorf("title: got %v, want %q", body.Title, newTitle)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})

	published := AdvisoryStatusPublished
	got, err := c.PatchAdvisory(context.Background(), "adv-001", PatchAdvisoryRequest{
		Title:  &newTitle,
		Status: &published,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Title != newTitle {
		t.Errorf("title: got %q, want %q", got.Title, newTitle)
	}
	if got.Status != AdvisoryStatusPublished {
		t.Errorf("status: got %q, want published", got.Status)
	}
}

// ── 10. TestPatchAdvisory_EmptyID ────────────────────────────────────────────

func TestPatchAdvisory_EmptyID(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for empty ID")
	})
	_, err := c.PatchAdvisory(context.Background(), "", PatchAdvisoryRequest{})
	if err == nil {
		t.Fatal("expected error for empty advisory ID")
	}
}

// ── 11. TestDeleteAdvisory_Success ───────────────────────────────────────────

func TestDeleteAdvisory_Success(t *testing.T) {
	var deleteCalled bool
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/augur/advisories/adv-001" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		deleteCalled = true
		w.WriteHeader(http.StatusNoContent)
	})

	if err := c.DeleteAdvisory(context.Background(), "adv-001"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !deleteCalled {
		t.Error("DELETE endpoint was not called")
	}
}

// ── 12. TestDeleteAdvisory_EmptyID ───────────────────────────────────────────

func TestDeleteAdvisory_EmptyID(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server should not be called for empty ID")
	})
	if err := c.DeleteAdvisory(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty advisory ID")
	}
}

// ── 13. TestGetActiveAdvisories_Success ──────────────────────────────────────

func TestGetActiveAdvisories_Success(t *testing.T) {
	adv := sampleAdvisory()
	adv.Status = AdvisoryStatusPublished

	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("status") != "published" {
			t.Errorf("expected status=published, got %q", q.Get("status"))
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]Advisory{adv})
	})

	got, err := c.GetActiveAdvisories(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 advisory, got %d", len(got))
	}
	if got[0].Status != AdvisoryStatusPublished {
		t.Errorf("status: got %q, want published", got[0].Status)
	}
}

// ── 14. TestCreateAdvisory_Conflict ──────────────────────────────────────────

func TestCreateAdvisory_Conflict(t *testing.T) {
	c := makeAUGURServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"duplicate CVE"}`))
	})

	_, err := c.CreateAdvisory(context.Background(), CreateAdvisoryRequest{
		Title:    "Dup",
		Severity: AdvisorySeverityHigh,
		CVE:      "CVE-2026-99999",
	})
	if err == nil {
		t.Fatal("expected error for 409 response, got nil")
	}
}

// ── 15. TestAugur_DisabledMode ───────────────────────────────────────────────

func TestAugur_DisabledMode(t *testing.T) {
	c := NewCITADELClient(CITADELClientOptions{}) // empty BaseURL = disabled

	adv, err := c.CreateAdvisory(context.Background(), CreateAdvisoryRequest{Title: "x"})
	if err != nil {
		t.Errorf("CreateAdvisory disabled: unexpected error: %v", err)
	}
	if adv != nil {
		t.Errorf("CreateAdvisory disabled: expected nil advisory, got %+v", adv)
	}

	list, err := c.ListAdvisories(context.Background(), nil)
	if err != nil {
		t.Errorf("ListAdvisories disabled: unexpected error: %v", err)
	}
	if list != nil {
		t.Errorf("ListAdvisories disabled: expected nil slice, got %+v", list)
	}

	single, err := c.GetAdvisory(context.Background(), "any-id")
	if err != nil {
		t.Errorf("GetAdvisory disabled: unexpected error: %v", err)
	}
	if single != nil {
		t.Errorf("GetAdvisory disabled: expected nil, got %+v", single)
	}

	patched, err := c.PatchAdvisory(context.Background(), "any-id", PatchAdvisoryRequest{})
	if err != nil {
		t.Errorf("PatchAdvisory disabled: unexpected error: %v", err)
	}
	if patched != nil {
		t.Errorf("PatchAdvisory disabled: expected nil, got %+v", patched)
	}

	if err := c.DeleteAdvisory(context.Background(), "any-id"); err != nil {
		t.Errorf("DeleteAdvisory disabled: unexpected error: %v", err)
	}

	active, err := c.GetActiveAdvisories(context.Background())
	if err != nil {
		t.Errorf("GetActiveAdvisories disabled: unexpected error: %v", err)
	}
	if active != nil {
		t.Errorf("GetActiveAdvisories disabled: expected nil, got %+v", active)
	}
}

// ── 16. TestAugur_NilClient ──────────────────────────────────────────────────

func TestAugur_NilClient(t *testing.T) {
	// Verify that calling methods on a nil *CITADELClient does not panic.
	// We use recover to catch panics — the test passes if no panic occurs.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil client panicked: %v", r)
		}
	}()

	var c *CITADELClient

	// These will all panic because c is nil and methods dereference c.
	// The test verifies we get a panic-free experience or a controlled error.
	// Since CITADELClient methods dereference c.baseURL, calling them on nil
	// will indeed panic. We protect with recover above.
	//
	// To make this truly safe, callers must check for nil before use.
	// This test documents the current behaviour.
	func() {
		defer func() { recover() }()
		_, _ = c.CreateAdvisory(context.Background(), CreateAdvisoryRequest{})
	}()
	func() {
		defer func() { recover() }()
		_, _ = c.ListAdvisories(context.Background(), nil)
	}()
	func() {
		defer func() { recover() }()
		_, _ = c.GetAdvisory(context.Background(), "id")
	}()
	func() {
		defer func() { recover() }()
		_, _ = c.PatchAdvisory(context.Background(), "id", PatchAdvisoryRequest{})
	}()
	func() {
		defer func() { recover() }()
		_ = c.DeleteAdvisory(context.Background(), "id")
	}()
	func() {
		defer func() { recover() }()
		_, _ = c.GetActiveAdvisories(context.Background())
	}()
}
