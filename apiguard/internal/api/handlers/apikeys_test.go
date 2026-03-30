package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// newTestAPIKeys returns an *APIKeys with a nop logger and nil dependencies.
// It mirrors the pattern used in findings_test.go: NewFindings(zerolog.Nop(), nil).
// The fourth argument (config) is nil; parseTrustedProxies handles nil safely.
func newTestAPIKeys(t *testing.T) *APIKeys {
	t.Helper()
	return NewAPIKeys(zerolog.Nop(), nil, nil, nil)
}

// ---- List validation --------------------------------------------------------

// TestAPIKeysList_InvalidPage verifies that a non-numeric page query param does
// not cause a 400 — the handler falls back to sensible defaults and only fails
// later at the DB call (nil). We wrap in recover() so the nil-DB panic is
// caught and we inspect only whether the status is NOT 400.
func TestAPIKeysList_InvalidPage(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys?page=notanumber", nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("invalid page query param should fall back to default, not return 400; body: %s", rec.Body.String())
	}
}

// TestAPIKeysList_NegativePage verifies that a negative page value is treated
// as the default (page=1) and does not return 400.
func TestAPIKeysList_NegativePage(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys?page=-5", nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("negative page should use default, not return 400; body: %s", rec.Body.String())
	}
}

// TestAPIKeysList_ZeroPage verifies that page=0 is treated as the default and
// does not return 400.
func TestAPIKeysList_ZeroPage(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-keys?page=0", nil)
	rec := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()

	if rec.Code == http.StatusBadRequest {
		t.Errorf("page=0 should use default, not return 400; body: %s", rec.Body.String())
	}
}

// ---- Create validation ------------------------------------------------------

// TestAPIKeysCreate_MalformedJSON verifies that malformed JSON in the request
// body produces a 400 Bad Request.
func TestAPIKeysCreate_MalformedJSON(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{not valid json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("malformed JSON: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeysCreate_EmptyBody verifies that an empty request body returns 400
// (json.Decoder returns an EOF error on empty input).
func TestAPIKeysCreate_EmptyBody(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty body: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeysCreate_NonObjectJSON verifies that a JSON value that is not an
// object (e.g. a bare array) is rejected with 400.
func TestAPIKeysCreate_NonObjectJSON(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", strings.NewReader(`["label","value"]`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("array JSON body: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---- Revoke validation ------------------------------------------------------

// TestAPIKeysRevoke_InvalidUUID verifies that a non-UUID id path parameter
// returns 400 before any DB access.
func TestAPIKeysRevoke_InvalidUUID(t *testing.T) {
	h := newTestAPIKeys(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/not-a-uuid", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid UUID: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeysRevoke_MissingID verifies that an absent chi route param (empty
// string) is treated as an invalid UUID and returns 400.
func TestAPIKeysRevoke_MissingID(t *testing.T) {
	h := newTestAPIKeys(t)

	// No chi context injected — URLParam returns "".
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/", nil)
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing id: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestAPIKeysRevoke_GarbageUUID verifies that a string that starts with a UUID
// structure but contains invalid characters is rejected with 400.
func TestAPIKeysRevoke_GarbageUUID(t *testing.T) {
	h := newTestAPIKeys(t)

	badID := "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+badID, nil)
	req = injectChiID(req, badID)
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("garbage UUID: want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
